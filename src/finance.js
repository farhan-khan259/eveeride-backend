import mongoose from "mongoose";
import * as M from "./models.js";
import {
  ensure,
  PLAN,
  FREE_PLAN,
  LEVELS,
  DEPOSIT_COMMISSION_RATES,
  Fault,
} from "./config.js";
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
export function take(wallet, amount, allowPromo = true, allowDeposit = true) {
  const out = { deposit: 0, earned: 0, promo: 0 };
  let left = amount;
  for (const k of [
    ...(allowDeposit ? ["deposit"] : []),
    "earned",
    ...(allowPromo ? ["promo"] : []),
  ]) {
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
const qualifiedSalaryLevels = (total) =>
  LEVELS.flatMap(([target], index) => (total >= target ? [index + 1] : []));
export async function ensureSalaryCycle(user, session, now = new Date()) {
  let cycle = await M.SalaryCycle.findOne({ user, current: true }).session(
    session,
  );
  if (cycle && cycle.endsAt > now) return cycle;
  if (cycle) {
    await M.SalaryCycle.updateOne(
      { _id: cycle.id, current: true },
      { $set: { current: false } },
      { session },
    );
  }
  const hasPreviousCycle = await M.SalaryCycle.exists({ user }).session(
      session,
    ),
    members = hasPreviousCycle
      ? []
      : await M.User.find({ ancestors: user }).select("_id").session(session),
    lastClaim = hasPreviousCycle
      ? null
      : await M.Transaction.findOne({ user, category: "salary_bonus" })
          .sort({ createdAt: -1 })
          .session(session),
    legacyLevels = hasPreviousCycle
      ? []
      : await M.SalaryBonus.find({ user, claimedAt: null })
          .select("level")
          .session(session),
    historicalTotal = hasPreviousCycle
      ? 0
      : (
          await M.Deposit.aggregate([
            {
              $match: {
                user: { $in: members.map((member) => member._id) },
                status: "approved",
                ...(lastClaim
                  ? { createdAt: { $gt: lastClaim.createdAt } }
                  : {}),
              },
            },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ]).session(session)
        )[0]?.total || 0,
    legacyTarget = Math.max(
      0,
      ...legacyLevels.map((item) => LEVELS[item.level - 1]?.[0] || 0),
    ),
    openingTotal = Math.max(historicalTotal, legacyTarget);
  const [created] = await M.SalaryCycle.create(
    [
      {
        user,
        startsAt: now,
        endsAt: new Date(+now + 10 * 86400000),
        total: openingTotal,
        current: true,
        qualifiedLevels: qualifiedSalaryLevels(openingTotal),
        claims: [],
      },
    ],
    { session },
  );
  return created;
}
export async function recordSalaryDeposit(user, amount, session) {
  const source = await M.User.findById(user).session(session);
  ensure(source, "User not found", 404);
  for (const ancestor of source.ancestors) {
    const cycle = await ensureSalaryCycle(ancestor, session);
    cycle.total += amount;
    cycle.qualifiedLevels = qualifiedSalaryLevels(cycle.total);
    await cycle.save({ session });
  }
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
export async function activateFreePlan(user, requestKey) {
  ensure(
    typeof requestKey === "string" &&
      requestKey.length >= 8 &&
      requestKey.length <= 100,
    "A valid activation request ID is required",
  );
  return atomic(async (s) => {
    const existing = await M.PlanPurchase.findOne({ user, requestKey }).session(
      s,
    );
    if (existing) return existing;
    ensure(
      !(await M.PlanPurchase.exists({ user, planType: "free" }).session(s)),
      "Your free plan has already been activated",
      409,
    );
    const now = new Date();
    const [plan] = await M.PlanPurchase.create(
      [
        {
          user,
          name: FREE_PLAN.name,
          price: 0,
          reward: FREE_PLAN.reward,
          planType: "free",
          start: now,
          expires: new Date(+now + FREE_PLAN.days * 86400000),
          sequence: 0,
          requestKey,
        },
      ],
      { session: s },
    );
    return plan;
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
    return r;
  });
}
export async function recordDepositCommissions(user, amount, event, session) {
  const source = await M.User.findById(user).session(session);
  ensure(source, "User not found", 404);
  const policy = await config(
    "referralPolicy",
    { enabled: false, reference: "" },
    session,
  );
  if (!policy.enabled || !policy.reference) return;
  for (let i = 0; i < DEPOSIT_COMMISSION_RATES.length; i++) {
    const ancestor = source.ancestors[i];
    if (!ancestor) continue;
    const commission = Math.floor(
      (amount * DEPOSIT_COMMISSION_RATES[i]) / 100,
    );
    if (!commission || !(await activePlan(ancestor, session))) continue;
    await award(
      ancestor,
      commission,
      `depositcommission:${event}:${i + 1}`,
      "team_commission",
      `Level ${i + 1} deposit commission`,
      session,
      event,
    );
    await M.Commission.create(
      [{
        user: ancestor,
        source: user,
        event: String(event),
        level: i + 1,
        amount: commission,
        kind: "deposit",
      }],
      { session },
    );
  }
}
