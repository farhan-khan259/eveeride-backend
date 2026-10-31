import mongoose from "mongoose";
import * as M from "./models.js";
import { ensure, PLAN, LEVELS, Fault } from "./config.js";
export async function atomic(fn) {
  return mongoose.connection.transaction(fn);
}
export async function config(key, fallback, session) {
  return (
    (await M.ApplicationConfiguration.findOne({ key }).session(session))
      ?.value ?? fallback
  );
}
export async function audit(
  admin,
  target,
  action,
  reason,
  before,
  after,
  reference,
  session,
) {
  ensure(
    reason?.trim()?.length >= 5,
    "Provide a reason of at least 5 characters",
  );
  return M.AdminAuditLog.create(
    [{ admin, target, action, reason, before, after, reference }],
    { session },
  );
}
export async function notify(user, title, message, session) {
  const u = await M.User.findById(user).session(session);
  await M.Notification.create([{ user, title, message }], { session });
  await M.Outbox.create(
    [{ user, email: u.email, subject: title, text: message }],
    { session },
  );
}
export async function ledger(
  user,
  key,
  category,
  amount,
  description,
  legs,
  session,
  reference,
) {
  ensure(
    legs.every((x) => Number.isSafeInteger(x.amount)) &&
      legs.reduce((s, x) => s + x.amount, 0) === 0,
    "Unbalanced ledger",
    500,
  );
  const [t] = await M.Transaction.create(
    [{ user, key, category, amount, description, legs, reference }],
    { session },
  );
  return t;
}
export async function award(
  user,
  amount,
  key,
  category,
  description,
  session,
  reference,
) {
  const u = await M.User.findByIdAndUpdate(
    user,
    { $inc: { "wallet.earned": amount } },
    { session, new: true },
  );
  ensure(u, "User missing", 404);
  const t = await ledger(
    user,
    key,
    category,
    amount,
    description,
    [
      { account: "rewardExpense", amount: -amount },
      { account: `${user}:earned`, amount },
    ],
    session,
    reference,
  );
  await notify(
    user,
    description,
    `Rs ${(amount / 100).toFixed(2)} credited.`,
    session,
  );
  return t;
}
export function take(wallet, amount, allowPromo = true) {
  const out = { deposit: 0, earned: 0, promo: 0 };
  let left = amount;
  for (const k of ["deposit", "earned", ...(allowPromo ? ["promo"] : [])]) {
    out[k] = Math.min(wallet[k] || 0, left);
    left -= out[k];
  }
  ensure(left === 0, "Insufficient available balance", 409);
  return out;
}
export async function activePlan(user, session, now = new Date()) {
  return M.PlanPurchase.exists({
    user,
    start: { $lte: now },
    expires: { $gt: now },
  }).session(session);
}
export async function purchase(user, requestKey) {
  ensure(
    typeof requestKey === "string" &&
      requestKey.length >= 8 &&
      requestKey.length <= 100,
    "A valid purchase request ID is required",
  );
  return atomic(async (s) => {
    const existing = await M.PlanPurchase.findOne({ user, requestKey }).session(
      s,
    );
    if (existing) return existing;
    const u = await M.User.findById(user).session(s);
    ensure(
      u.purchases < 3,
      "Your maximum plan purchase limit has been reached",
      409,
    );
    const cuts = take(u.wallet, PLAN.price, false);
    if (!u.promoUnlocked) {
      await ledger(
        user,
        `promo-backing:${user}`,
        "registration_backing",
        0,
        "Promotional balance covered by plan activation",
        [
          { account: "planReceipts", amount: -u.wallet.promo },
          { account: "promotionalExpense", amount: u.wallet.promo },
        ],
        s,
      );
      u.promoUnlocked = true;
    }
    for (const k of Object.keys(cuts)) u.wallet[k] -= cuts[k];
    u.purchases++;
    await u.save({ session: s });
    const now = new Date();
    const [p] = await M.PlanPurchase.create(
      [
        {
          user,
          name: PLAN.name,
          price: PLAN.price,
          reward: PLAN.reward,
          start: now,
          expires: new Date(+now + PLAN.days * 86400000),
          sequence: u.purchases,
          requestKey,
        },
      ],
      { session: s },
    );
    await ledger(
      user,
      `purchase:${p.id}`,
      "plan_purchase",
      -PLAN.price,
      "Starter Plan activated",
      [
        ...Object.entries(cuts)
          .filter(([, n]) => n)
          .map(([k, n]) => ({ account: `${user}:${k}`, amount: -n })),
        { account: "planReceipts", amount: PLAN.price },
      ],
      s,
      p.id,
    );
    return p;
  });
}
export async function recordRevenue(admin, user, amount, externalRef, reason) {
  return atomic(async (s) => {
    const source = await M.User.findById(user).session(s);
    ensure(source, "User not found", 404);
    const [r] = await M.Revenue.create(
      [{ user, amount, externalRef, reason, verifiedBy: admin }],
      { session: s },
    );
    await audit(
      admin,
      user,
      "verify_business_revenue",
      reason,
      null,
      { amount, externalRef },
      r.id,
      s,
    );
    await ledger(
      user,
      `revenue:${r.id}`,
      "business_revenue",
      0,
      "Verified external business activity",
      [
        { account: "businessCash", amount },
        { account: "businessRevenue", amount: -amount },
      ],
      s,
      r.id,
    );
    const policy = await config(
      "referralPolicy",
      { enabled: false, reference: "" },
      s,
    );
    if (policy.enabled && policy.reference) {
      for (let i = 0; i < source.ancestors.length; i++) {
        const ancestor = source.ancestors[i],
          n = Math.floor((amount * [8, 4, 2, 1][i]) / 100);
        if (n && (await activePlan(ancestor, s))) {
          await award(
            ancestor,
            n,
            `commission:${r.id}:${i}`,
            "team_commission",
            "Revenue referral reward",
            s,
            r.id,
          );
          await M.Commission.create(
            [
              {
                user: ancestor,
                source: user,
                event: r.id,
                level: i + 1,
                amount: n,
                kind: "revenue",
              },
            ],
            { session: s },
          );
        }
      }
    }
    for (const ancestor of source.ancestors) {
      const members = await M.User.find({ ancestors: ancestor })
        .select("_id")
        .session(s);
      const total =
        (
          await M.Revenue.aggregate([
            { $match: { user: { $in: members.map((x) => x._id) } } },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ]).session(s)
        )[0]?.total || 0;
      for (let i = 0; i < LEVELS.length; i++)
        if (total >= LEVELS[i][0])
          await M.SalaryBonus.updateOne(
            { user: ancestor, level: i + 1 },
            {
              $setOnInsert: {
                qualifiedAt: new Date(),
                claimAfter: new Date(Date.now() + 10 * 86400000),
              },
            },
            { upsert: true, session: s },
          );
    }
    return r;
  });
}
