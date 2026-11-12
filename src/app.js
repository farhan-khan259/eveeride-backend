import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import multer from "multer";
import path from "node:path";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import { z } from "zod";
import mongoose from "mongoose";
import {
  cfg,
  ensure,
  Fault,
  PLAN,
  FREE_PLAN,
  LEVELS,
  DEPOSIT_COMMISSION_RATES,
  TEAM_EARNING_COMMISSION_RATE,
  hoursOpen,
  money,
  dayKey,
} from "./config.js";
import * as M from "./models.js";
import {
  auth,
  admin,
  sign,
  signImpersonation,
  readOnlyImpersonation,
  seal,
  unseal,
  hash,
} from "./security.js";
import {
  atomic,
  config,
  audit,
  notify,
  ledger,
  award,
  take,
  activePlan,
  purchase,
  activateFreePlan,
  recordRevenue,
  ensureSalaryCycle,
  recordSalaryDeposit,
  recordDepositCommissions,
} from "./finance.js";
export const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: cfg.origins }));
app.use(express.json({ limit: "64kb" }));
const apiLimit = rateLimit({ windowMs: 60000, limit: 180 });
app.use((req, res, next) => {
  if (req.path === "/api/auth/login" || req.path === "/api/auth/register")
    return next();
  return apiLimit(req, res, next);
});
const route = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res)).catch(next);
const id = (x) => {
  ensure(mongoose.isValidObjectId(x), "Invalid record ID");
  return x;
};
const page = (q) => Math.max(1, Math.min(10000, parseInt(q.page) || 1));
const transactionPageSize = 10;
const text = (x, min = 1, max = 500) =>
  z.string().trim().min(min).max(max).parse(x);
const paymentsLive = () => {
  ensure(cfg.live, "Payment requests are currently unavailable", 503);
};
const withdrawalsLive = () => {
  paymentsLive();
  ensure(
    hoursOpen(),
    "Requests are available only from 8:00 AM to 5:00 PM Pakistan time",
    403,
  );
};
const password = z
  .string()
  .min(8)
  .max(100)
  .regex(/[A-Z]/, "Include an uppercase letter")
  .regex(/[a-z]/, "Include a lowercase letter")
  .regex(/[0-9]/, "Include a number");
const uploadDir = path.resolve(process.env.UPLOAD_DIR || "uploads");
await fs.mkdir(uploadDir, { recursive: true });
function uploadPath(storedFile) {
  const filename = path.basename(String(storedFile || ""));
  ensure(filename && filename !== "." && filename !== "..", "Invalid stored file");
  return path.join(uploadDir, filename);
}
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (_req, _file, cb) => cb(null, crypto.randomUUID()),
  }),
  limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  fileFilter: (req, f, cb) =>
    cb(
      null,
      req.path.includes("videos")
        ? f.mimetype === "video/mp4"
        : ["image/png", "image/jpeg", "image/webp"].includes(f.mimetype),
    ),
});
async function validateFile(file, video = false) {
  ensure(file, "A valid file is required");
  const b = await fs.readFile(file.path);
  const ok = video
    ? b.subarray(4, 8).toString() === "ftyp"
    : (b[0] === 255 && b[1] === 216 && b[2] === 255) ||
      b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ||
      (b.subarray(0, 4).toString() === "RIFF" &&
        b.subarray(8, 12).toString() === "WEBP");
  ensure(ok, "File content does not match an allowed format");
  ensure(video || b.length <= 5 * 1024 * 1024, "Image must be under 5 MB");
}
app.get("/api/health", (_req, res) =>
  res.json({
    status:
      mongoose.connection.readyState === 1 ? "ok" : "database-unavailable",
  }),
);
app.get(
  "/api/public",
  route(async (_req, res) =>
    res.json({
      plan: PLAN,
      levels: LEVELS,
      serverTime: new Date(),
      hoursOpen: hoursOpen(),
      paymentsEnabled: cfg.live,
      support: cfg.support,
      business: cfg.business,
      policy: "Team progress includes eligible activity from four referral levels.",
      commissions: {
        deposit: DEPOSIT_COMMISSION_RATES,
        teamEarning: [TEAM_EARNING_COMMISSION_RATE],
      },
      subscribers: (await M.PlanPurchase.distinct("user")).length,
    }),
  ),
);
// Apply a separate limit to password recovery endpoints only.
const authActionLimit = rateLimit({
  windowMs: 15 * 60000,
  limit: 60,
  skipSuccessfulRequests: true,
  handler: (_req, res) =>
    res.status(429).json({
      message: "Too many requests. Please wait a few minutes and try again.",
    }),
});
app.post(
  "/api/auth/register",
  route(async (req, res) => {
    const b = z
      .object({
        name: z.string().trim().min(2).max(80),
        username: z
          .string()
          .regex(/^[a-zA-Z0-9_]{3,30}$/)
          .transform((x) => x.toLowerCase())
          .optional(),
        email: z
          .string()
          .email()
          .max(254)
          .transform((x) => x.toLowerCase()),
        password,
        confirmPassword: z.string(),
        referralCode: z.string().max(30).optional(),
        terms: z.literal(true),
      })
      .parse(req.body);
    ensure(b.password === b.confirmPassword, "Passwords do not match");
    const pw = await bcrypt.hash(b.password, 12);
    const u = await atomic(async (s) => {
      const ref = b.referralCode
        ? await M.User.findOne({
            referralCode: b.referralCode,
            status: "active",
          }).session(s)
        : null;
      ensure(!b.referralCode || ref, "Invalid referral code");
      ensure(
        !(await M.User.exists({ email: b.email }).session(s)),
        "An account with this email already exists. Please sign in instead.",
        409,
      );
      const username =
        b.username ||
        `${b.name.toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 20) || "user"}-${crypto.randomBytes(3).toString("hex")}`;
      const [u] = await M.User.create(
        [
          {
            name: b.name,
            username,
            email: b.email,
            password: pw,
            referralCode: crypto.randomBytes(6).toString("hex").toUpperCase(),
            referrer: ref?._id,
            ancestors: ref ? [ref._id, ...ref.ancestors].slice(0, 4) : [],
            wallet: { deposit: 0, earned: 0, promo: 2000, pending: 0 },
          },
        ],
        { session: s },
      );
      await M.ReferralRelationship.create(
        [{ user: u._id, ancestors: u.ancestors }],
        { session: s },
      );
      await ledger(
        u.id,
        `registration:${u.id}`,
        "registration_bonus",
        2000,
        "Registration bonus · locked until paid-plan eligibility",
        [
          { account: "promotionalExpense", amount: -2000 },
          { account: `${u.id}:promo`, amount: 2000 },
        ],
        s,
      );
      await notify(
        u.id,
        "Welcome to EveeRide",
        "Your Rs 20 promotional bonus is locked until paid-plan eligibility.",
        s,
      );
      return u;
    });
    res.status(201).json({ token: sign(u), user: publicUser(u) });
  }),
);
function publicUser(u) {
  const registeredAt = u.createdAt || u._id?.getTimestamp?.();
  return {
    id: u.id,
    name: u.name,
    username: u.username,
    email: u.email,
    role: u.role,
    status: u.status,
    referralCode: u.referralCode,
    wallet: u.wallet,
    purchases: u.purchases,
    createdAt: registeredAt,
    avatarVersion: u.avatar ? u.updatedAt : null,
  };
}
app.post(
  "/api/auth/login",
  route(async (req, res) => {
    const email = text(req.body.email, 3, 254).toLowerCase(),
      pw = text(req.body.password, 1, 100);
    const u = await M.User.findOne({ email }).select("+password");
    ensure(
      u && (await bcrypt.compare(pw, u.password)),
      "Email or password is incorrect",
      401,
    );
    ensure(u.status === "active", "Account suspended", 403);
    res.json({ token: sign(u), user: publicUser(u) });
  }),
);
app.post(
  "/api/auth/forgot",
  authActionLimit,
  route(async (req, res) => {
    const email = z.string().email().parse(req.body.email).toLowerCase(),
      otp = String(crypto.randomInt(100000, 1000000));
    await atomic(async (s) => {
      const u = await M.User.findOne({ email })
        .select("+resetRequestedAt")
        .session(s);
      const canSend =
        u &&
        (!u.resetRequestedAt ||
          Date.now() - u.resetRequestedAt.getTime() >= 30000);
      if (canSend) {
        u.resetHash = hash(otp);
        u.resetExpires = new Date(Date.now() + 10 * 60000);
        u.resetRequestedAt = new Date();
        await u.save({ session: s });
        await M.Outbox.create(
          [
            {
              user: u.id,
              email,
              subject: "Your EveeRide password reset OTP",
              text: `Your EveeRide password reset OTP is ${otp}. It expires in 10 minutes. If you did not request this code, you can ignore this email.`,
            },
          ],
          { session: s },
        );
      }
    });
    res.json({
      message: "If that email is registered, a six-digit OTP will be sent.",
    });
  }),
);
app.post(
  "/api/auth/reset",
  authActionLimit,
  route(async (req, res) => {
    const body = z
        .object({
          email: z.string().email().transform((value) => value.toLowerCase()),
          otp: z.string().regex(/^\d{6}$/, "Enter the six-digit OTP"),
          password,
          confirmPassword: z.string().min(1).max(100),
        })
        .parse(req.body),
      p = body.password,
      pw = await bcrypt.hash(p, 12);
    ensure(
      body.password === body.confirmPassword,
      "New password confirmation does not match",
    );
    await atomic(async (s) => {
      const u = await M.User.findOne({
        email: body.email,
        resetHash: hash(body.otp),
        resetExpires: { $gt: new Date() },
      })
        .select("+resetHash +resetRequestedAt")
        .session(s);
      ensure(u, "OTP is invalid or expired");
      u.password = pw;
      u.resetHash = undefined;
      u.resetExpires = undefined;
      u.resetRequestedAt = undefined;
      u.sessionVersion++;
      await u.save({ session: s });
    });
    res.json({ message: "Password reset successfully. Please sign in." });
  }),
);
app.use("/api", auth);
app.use("/api", readOnlyImpersonation);
app.get(
  "/api/me",
  route(async (req, res) => res.json(publicUser(req.user))),
);
app.get(
  "/api/account/avatar",
  route(async (req, res) => {
    const u = await M.User.findById(req.user.id).select("avatar avatarMime");
    ensure(u?.avatar, "Profile picture not found", 404);
    res.set("Cache-Control", "private, no-store");
    res.type(u.avatarMime || "application/octet-stream");
    res.sendFile(path.resolve(uploadDir, u.avatar));
  }),
);
app.post(
  "/api/account/avatar",
  upload.single("avatar"),
  route(async (req, res) => {
    await validateFile(req.file);
    const u = await M.User.findById(req.user.id);
    ensure(u, "User not found", 404);
    const previous = u.avatar;
    u.avatar = req.file.filename;
    u.avatarMime = req.file.mimetype;
    await u.save();
    if (previous && previous !== u.avatar)
      await fs.unlink(path.resolve(uploadDir, previous)).catch(() => {});
    res.json({
      message: previous ? "Profile picture updated" : "Profile picture added",
      user: publicUser(u),
    });
  }),
);
app.post(
  "/api/account/password",
  route(async (req, res) => {
    const body = z
      .object({
        currentPassword: z.string().min(1).max(100),
        newPassword: password,
        confirmPassword: z.string().min(1).max(100),
      })
      .parse(req.body);
    ensure(
      body.newPassword === body.confirmPassword,
      "New password confirmation does not match",
    );
    const u = await M.User.findById(req.user.id).select("+password");
    ensure(
      await bcrypt.compare(body.currentPassword, u.password),
      "Current password is incorrect",
      403,
    );
    ensure(
      !(await bcrypt.compare(body.newPassword, u.password)),
      "New password must be different from the current password",
    );
    u.password = await bcrypt.hash(body.newPassword, 12);
    u.sessionVersion++;
    await u.save();
    res.json({
      message: "Password updated successfully",
      token: sign(u),
      user: publicUser(u),
    });
  }),
);
app.post(
  "/api/auth/logout",
  route(async (req, res) => {
    await M.User.updateOne(
      { _id: req.user.id },
      { $inc: { sessionVersion: 1 } },
    );
    res.json({ message: "Signed out" });
  }),
);
async function snapshot(user) {
  const u = await M.User.findById(user),
    plans = await M.PlanPurchase.find({ user }).sort({ createdAt: -1 }),
    active = plans.filter((x) => x.expires > new Date());
  const totals = await M.Transaction.aggregate([
    { $match: { user: u._id } },
    { $group: { _id: "$category", amount: { $sum: "$amount" } } },
  ]),
    totalEarnings = await M.Transaction.aggregate([
      {
        $match: {
          user: u._id,
          amount: { $gt: 0 },
          category: {
            $nin: [
              "deposit",
              "plan_purchase",
              "registration_backing",
              "withdrawal",
            ],
          },
        },
      },
      { $group: { _id: null, amount: { $sum: "$amount" } } },
    ]);
  return {
    user: publicUser(u),
    plans,
    activePlans: active,
    available: u.wallet.deposit + u.wallet.earned + u.wallet.promo,
    depositBalance: u.wallet.deposit,
    totalEarnings: totalEarnings[0]?.amount || 0,
    withdrawable: active.length
      ? u.wallet.earned + (u.promoUnlocked ? u.wallet.promo : 0)
      : 0,
    pending: u.wallet.pending,
    totals: Object.fromEntries(totals.map((x) => [x._id, x.amount])),
    recent: await M.Transaction.find({
      user,
      category: { $ne: "registration_backing" },
    })
      .sort({ createdAt: -1 })
      .limit(5),
    serverTime: new Date(),
  };
}
app.get(
  "/api/dashboard",
  route(async (req, res) => res.json(await snapshot(req.user.id))),
);
app.get(
  "/api/plans",
  route(async (req, res) =>
    res.json({
      plan: PLAN,
      freePlan: FREE_PLAN,
      purchases: await M.PlanPurchase.find({
        user: req.user.id,
        planType: "paid",
      }),
      freePurchase: await M.PlanPurchase.findOne({
        user: req.user.id,
        planType: "free",
      }),
      subscribers: (await M.PlanPurchase.distinct("user")).length,
    }),
  ),
);
app.post(
  "/api/plans/purchase",
  route(async (req, res) =>
    res.status(201).json(await purchase(req.user.id, req.body.requestId)),
  ),
);
app.post(
  "/api/plans/free/activate",
  route(async (req, res) =>
    res.status(201).json(
      await activateFreePlan(req.user.id, req.body.requestId),
    ),
  ),
);
app.get(
  "/api/tasks",
  route(async (req, res) => {
    const now = new Date(),
      plans = await M.PlanPurchase.find({
        user: req.user.id,
        expires: { $gt: now },
        start: { $lte: now },
      }),
      tasks = await M.Task.find({ active: true });
    const assignments = [];
    for (let i = 0; tasks.length && i < plans.length; i++) {
      const p = plans[i],
        latest = await M.TaskAssignment.findOne({ purchase: p.id }).sort({
          createdAt: -1,
        }),
        eligibleAt = latest?.expires,
        eligible = !latest || !eligibleAt || eligibleAt <= now;
      if (eligible) {
        await M.TaskAssignment.updateOne(
          { purchase: p.id, day: dayKey() },
          {
            $setOnInsert: {
              user: req.user.id,
              purchase: p.id,
              task: tasks[0]._id,
              day: dayKey(),
              expires: new Date(Math.min(+p.expires, +now + 86400000)),
              reward: p.reward,
            },
          },
          { upsert: true },
        ).catch((e) => {
          if (e.code !== 11000) throw e;
        });
        assignments.push(
          await M.TaskAssignment.findOne({
            purchase: p.id,
            day: dayKey(),
          })
            .populate("task")
            .populate("purchase", "planType name"),
        );
      } else {
        await latest.populate([
          { path: "task" },
          { path: "purchase", select: "planType name" },
        ]);
        assignments.push(latest);
      }
    }
    res.json(assignments.filter(Boolean));
  }),
);
app.get(
  "/api/tasks/history",
  route(async (req, res) => {
    const currentPage = page(req.query),
      limit = 10,
      filter = {
      user: req.user.id,
      completed: { $ne: null },
      },
      history = await M.TaskAssignment.find(filter)
      .sort({ completed: -1 })
      .skip((currentPage - 1) * limit)
      .limit(limit)
      .populate("task", "title duration")
      .populate("purchase", "planType name");
    res.json({
      items: history,
      total: await M.TaskAssignment.countDocuments(filter),
      page: currentPage,
    });
  }),
);
app.post(
  "/api/tasks/:id/start",
  route(async (req, res) => {
    const t = await M.TaskAssignment.findOne({
      _id: id(req.params.id),
      user: req.user.id,
    }).populate("purchase");
    ensure(
      t &&
        !t.completed &&
        t.expires > new Date() &&
        t.purchase.expires > new Date(),
      "Task is completed or expired",
    );
    await M.TaskAssignment.updateOne(
      { _id: t.id, started: null },
      { $set: { started: new Date() } },
    );
    res.json({ message: "Task started", serverTime: new Date() });
  }),
);
app.post(
  "/api/tasks/:id/complete",
  route(async (req, res) =>
    res.json(
      await atomic(async (s) => {
        const t = await M.TaskAssignment.findOne({
          _id: id(req.params.id),
          user: req.user.id,
        })
          .populate("task purchase")
          .session(s);
        ensure(
          t && !t.completed,
          "This task has already been completed or is invalid",
          409,
        );
        ensure(
          t.started &&
            t.expires > new Date() &&
            t.purchase.expires > new Date(),
          "Task is expired or has not started",
        );
        ensure(
          Date.now() - t.started >= t.task.duration * 1000,
          "Please complete the minimum task duration",
        );
        ensure(
          process.env.TASK_REWARD_MODE === "internal-sponsored",
          "Task rewards require an approved provider verification integration",
          503,
        );
        t.completed = new Date();
        t.expires = new Date(
          Math.min(+t.purchase.expires, +t.completed + 86400000),
        );
        await t.save({ session: s });
        await award(
          req.user.id,
          t.reward,
          `task:${t.id}`,
          "task_earning",
          "Task reward",
          s,
          t.id,
        );
        const policy = await config(
          "referralPolicy",
          { taskEnabled: false },
          s,
        );
        if (
          policy.taskEnabled &&
          policy.reference &&
          req.user.ancestors[0] &&
          (await activePlan(req.user.ancestors[0], s))
        ) {
          const n = Math.floor(
            (t.reward * TEAM_EARNING_COMMISSION_RATE) / 100,
          );
          await award(
            req.user.ancestors[0],
            n,
            `taskcommission:${t.id}`,
            "team_task_commission",
            "Direct-team task reward",
            s,
            t.id,
          );
          await M.Commission.create(
            [
              {
                user: req.user.ancestors[0],
                source: req.user.id,
                event: t.id,
                level: 1,
                amount: n,
                kind: "task",
              },
            ],
            { session: s },
          );
        }
        return {
          message: "Task completed. Reward credited.",
          reward: t.reward,
        };
      }),
    ),
  ),
);
app.get(
  "/api/files/tasks/:id",
  route(async (req, res) => {
    const t = await M.Task.findById(id(req.params.id));
    ensure(t, "Video not found", 404);
    ensure(
      req.user.role === "admin" ||
        (await M.TaskAssignment.exists({ user: req.user.id, task: t.id })),
      "Not authorized",
      403,
    );
    const file = uploadPath(t.file);
    const stat = await fs.stat(file).catch(() => null);
    ensure(stat?.isFile(), "Video file is missing from storage", 404);
    res.set("Cache-Control", "private, no-store");
    res.type(t.mime || "video/mp4").sendFile(file, (error) => {
        if (error && !res.headersSent) res.status(404).json({ message: "Video file could not be served" });
    });
  }),
);
app.get(
  "/api/payments",
  route(async (_req, res) => {
    const methods = await config("payments", {});
    res.json({
      methods: Object.fromEntries(
        Object.entries(methods).filter(([, v]) => v.enabled),
      ),
      hoursOpen: hoursOpen(),
      serverTime: new Date(),
      paymentsEnabled: cfg.live,
    });
  }),
);
app.post(
  "/api/deposits/order",
  route(async (req, res) => {
    paymentsLive();
    const amount = money(req.body.amount),
      method = z
        .enum(["EasyPaisa", "JazzCash", "Mashreq"])
        .parse(req.body.method);
    ensure(amount >= 51000, "Minimum deposit is Rs 510");
    const methods = await config("payments", {}),
      account = methods[method];
    ensure(
      account?.enabled && account.title && account.number,
      "This payment account is not configured",
    );
    const d = await M.Deposit.create({
      user: req.user.id,
      amount,
      method,
      expires: new Date(Date.now() + 15 * 60000),
    });
    res.status(201).json({ order: d, account, serverTime: new Date() });
  }),
);
app.post(
  "/api/deposits/:id/submit",
  upload.single("screenshot"),
  route(async (req, res) => {
    paymentsLive();
    await validateFile(req.file);
    const tid = text(req.body.tid, 6, 80);
    const d = await atomic(async (s) => {
      const d = await M.Deposit.findOne({
        _id: id(req.params.id),
        user: req.user.id,
      }).session(s);
      ensure(
        d && d.status === "awaiting",
        "Deposit already submitted or invalid",
        409,
      );
      if (d.expires < new Date()) {
        d.status = "expired";
        await d.save({ session: s });
        return d;
      }
      d.tid = tid;
      d.file = req.file.filename;
      d.status = "pending";
      await d.save({ session: s });
      await notify(
        req.user.id,
        "Deposit submitted",
        "Your deposit is pending verification.",
        s,
      );
      return d;
    });
    ensure(
      d.status !== "expired",
      "Payment order expired. Create a new order.",
    );
    res.json(d);
  }),
);
app.get(
  "/api/payout-account",
  route(async (req, res) => {
    const a = await M.PayoutAccount.findOne({ user: req.user.id });
    res.json(a ? unseal(a.cipher) : null);
  }),
);
app.put(
  "/api/payout-account",
  route(async (req, res) => {
    const b = z
      .object({
        holder: z.string().trim().min(3).max(100),
        number: z.string().regex(/^[A-Za-z0-9 -]{10,40}$/),
        type: z.enum(["EasyPaisa", "JazzCash", "Bank Account"]),
        bank: z.string().max(100).optional(),
        password: z.string().max(100),
      })
      .parse(req.body);
    ensure(
      b.type !== "Bank Account" || b.bank?.length >= 2,
      "Bank name is required",
    );
    const u = await M.User.findById(req.user.id).select("+password");
    ensure(
      await bcrypt.compare(b.password, u.password),
      "Password verification failed",
      403,
    );
    delete b.password;
    await atomic(async (s) => {
      ensure(
        !(await M.PayoutAccount.exists({ user: u.id }).session(s)),
        "Your payout account is permanently bound and cannot be changed",
        409,
      );
      await M.User.updateOne(
        { _id: u.id },
        { $inc: { sessionVersion: 0 } },
        { session: s },
      );
      await M.PayoutAccount.create(
        [{ user: u.id, cipher: seal(b) }],
        { session: s },
      );
    });
    res.json({ message: "Payout account permanently bound" });
  }),
);
app.post(
  "/api/withdrawals",
  route(async (req, res) => {
    withdrawalsLive();
    const amount = money(req.body.amount);
    ensure(amount >= 10000, "Minimum withdrawal is Rs 100");
    const w = await atomic(async (s) => {
      const u = await M.User.findById(req.user.id).session(s);
      ensure(
        await activePlan(u.id, s),
        "An active plan is required to withdraw",
      );
      ensure(
        !(await M.Withdrawal.exists({
          user: u.id,
          status: "pending",
        }).session(s)),
        "A withdrawal is already pending. Approve or reject it before creating another.",
      );
      const a = await M.PayoutAccount.findOne({ user: u.id }).session(s);
      ensure(a, "Bind a payout account first");
      const cuts = take(u.wallet, amount, u.promoUnlocked, false);
      for (const k of Object.keys(cuts)) u.wallet[k] -= cuts[k];
      u.wallet.pending += amount;
      await u.save({ session: s });
      const [w] = await M.Withdrawal.create(
        [
          {
            user: u.id,
            amount,
            account: { cipher: a.cipher },
            reservation: cuts,
          },
        ],
        { session: s },
      );
      await ledger(
        u.id,
        `withdrawal:${w.id}`,
        "withdrawal_reservation",
        -amount,
        "Withdrawal request submitted",
        Object.entries(cuts)
          .filter(([, n]) => n)
          .map(([k, n]) => ({ account: `${u.id}:${k}`, amount: -n }))
          .concat({ account: `${u.id}:pending`, amount }),
        s,
        w.id,
      );
      await notify(
        u.id,
        "Withdrawal submitted",
        "Request submitted, awaiting approval. No tax deducted.",
        s,
      );
      return w;
    });
    res.status(201).json({
      id: w.id,
      amount: w.amount,
      status: w.status,
      createdAt: w.createdAt,
      message: "Withdrawal request submitted. Awaiting approval.",
    });
  }),
);
app.get(
  "/api/requests",
  route(async (req, res) =>
    res.json({
      deposits: await M.Deposit.find({ user: req.user.id })
        .sort({ createdAt: -1 })
        .limit(100),
      withdrawals: await M.Withdrawal.find({ user: req.user.id })
        .select("-account")
        .sort({ createdAt: -1 })
        .limit(100),
    }),
  ),
);
app.get(
  "/api/team",
  route(async (req, res) => {
    const now = new Date();
    const members = await M.User.find({ ancestors: req.user._id }).select(
      "_id name ancestors createdAt",
    );
    const ids = members.map((x) => x._id),
      sum = async (model, match) =>
        (
          await model.aggregate([
            { $match: match },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
        )[0]?.total || 0,
      memberDepositRows = await M.Deposit.aggregate([
        { $match: { user: { $in: ids }, status: "approved" } },
        { $group: { _id: "$user", total: { $sum: "$amount" } } },
      ]),
      memberDeposits = new Map(
        memberDepositRows.map((x) => [String(x._id), x.total]),
      ),
      activePlanIds = new Set(
        (
          await M.PlanPurchase.distinct("user", {
            user: { $in: ids },
            start: { $lte: now },
            expires: { $gt: now },
          })
        ).map(String),
      );
    res.json({
      members: members.map((x) => ({
        id: x.id,
        name: x.name,
        level: x.ancestors.findIndex((a) => a.equals(req.user._id)) + 1,
        joined: x.createdAt,
        deposits: memberDeposits.get(String(x._id)) || 0,
        active: activePlanIds.has(String(x._id)),
      })),
      levels: [0, 1, 2, 3].map(
        (i) =>
          members.filter((x) => x.ancestors[i]?.equals(req.user._id)).length,
      ),
      deposits: await sum(M.Deposit, {
        user: { $in: ids },
        status: "approved",
      }),
      withdrawals: await sum(M.Withdrawal, {
        user: { $in: ids },
        status: "approved",
      }),
      revenue: await sum(M.Revenue, { user: { $in: ids } }),
      earnings: await sum(M.Transaction, {
        user: { $in: ids },
        category: "task_earning",
      }),
      commissions: await sum(M.Commission, { user: req.user._id }),
      salary: await sum(M.Transaction, {
        user: req.user._id,
        category: "salary_bonus",
      }),
      pendingRewards: 0,
      referralUrl: `${cfg.web}/register?ref=${req.user.referralCode}`,
    });
  }),
);
app.get(
  "/api/salary",
  route(async (req, res) => {
    const cycle = await atomic((s) => ensureSalaryCycle(req.user.id, s)),
      cycles = await M.SalaryCycle.find({
        user: req.user.id,
        qualifiedLevels: { $exists: true, $ne: [] },
      }).sort({ startsAt: 1 }),
      states = LEVELS.flatMap((_, index) => {
        const level = index + 1,
          pending = cycles.find(
            (item) =>
              item.qualifiedLevels.includes(level) &&
              !item.claims.some((claim) => claim.level === level),
          ),
          currentClaim = cycle.claims.find((claim) => claim.level === level);
        if (pending)
          return [
            {
              level,
              qualifiedAt: pending.startsAt,
              claimAfter: pending.endsAt,
              cycle: pending.id,
            },
          ];
        if (currentClaim)
          return [
            {
              level,
              qualifiedAt: cycle.startsAt,
              claimAfter: cycle.endsAt,
              claimedAt: currentClaim.claimedAt,
              cycle: cycle.id,
            },
          ];
        return [];
      });
    res.json({
      total: cycle.total,
      cycleStartsAt: cycle.startsAt,
      cycleEndsAt: cycle.endsAt,
      serverTime: new Date(),
      levels: LEVELS.map(([target, bonus], i) => ({
        level: i + 1,
        target,
        bonus,
      })),
      states,
    });
  }),
);
app.post(
  "/api/salary/:level/claim",
  route(async (req, res) =>
    res.json(
      await atomic(async (s) => {
        ensure(await activePlan(req.user.id, s), "Active paid plan required");
        const level = Number(req.params.level),
          b = await M.SalaryCycle.findOne({
            user: req.user.id,
            qualifiedLevels: level,
            "claims.level": { $ne: level },
          })
            .sort({ startsAt: 1 })
            .session(s);
        ensure(b, "Bonus not qualified or already claimed", 409);
        ensure(
          b.endsAt <= new Date(),
          "The ten-day waiting period has not ended",
        );
        const policy = await config("bonusPolicy", { enabled: false }, s);
        ensure(
          policy.enabled && policy.reference,
          "Bonus payout policy requires approval",
          503,
        );
        const t = await award(
          req.user.id,
          LEVELS[level - 1][1],
          `salary:${b.id}:${level}`,
          "salary_bonus",
          `Level ${level} cycle salary reward`,
          s,
          b.id,
        );
        await M.SalaryCycle.updateOne(
          { _id: b.id, "claims.level": { $ne: level } },
          {
            $push: {
              claims: { level, claimedAt: new Date(), transaction: t.id },
            },
          },
          { session: s },
        );
        return { message: "Salary reward credited" };
      }),
    ),
  ),
);
app.post(
  "/api/promos/claim",
  route(async (req, res) =>
    res.json(
      await atomic(async (s) => {
        ensure(
          await activePlan(req.user.id, s),
          "An active paid plan is required to claim a code",
        );
        const p = await M.PromoCode.findOne({
          code: text(req.body.code, 2, 40).toUpperCase(),
        }).session(s);
        ensure(
          p?.active && p.starts <= new Date() && p.expires > new Date(),
          "The promo code is invalid, expired or disabled",
        );
        ensure(
          p.claims < p.maxClaims && p.reward * (p.claims + 1) <= p.budget,
          "Promo budget exhausted",
        );
        await M.PromoCodeClaim.create(
          [{ user: req.user.id, promo: p.id, amount: p.reward }],
          { session: s },
        );
        p.claims++;
        await p.save({ session: s });
        await award(
          req.user.id,
          p.reward,
          `promo:${p.id}:${req.user.id}`,
          "promo_reward",
          "Promo-code reward",
          s,
          p.id,
        );
        return { message: `Rs ${(p.reward / 100).toFixed(2)} credited` };
      }),
    ),
  ),
);
app.get(
  "/api/promos/claims",
  route(async (req, res) =>
    res.json(
      await M.PromoCodeClaim.find({ user: req.user.id })
        .populate("promo", "code")
        .sort({ createdAt: -1 })
        .limit(100),
    ),
  ),
);
function transactionFilter(q, user) {
  const f = user ? { user } : {};
  if (q.user) f.user = id(q.user);
  if (q.category) f.category = text(q.category, 1, 60);
  if (q.status) f.status = text(q.status, 1, 20);
  if (q.search)
    f.$or = [
      {
        description: {
          $regex: text(q.search, 1, 80).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
          $options: "i",
        },
      },
      { reference: text(q.search, 1, 80) },
    ];
  if (q.from || q.to) {
    f.createdAt = {};
    if (q.from) {
      ensure(!isNaN(Date.parse(q.from)), "Invalid start date");
      f.createdAt.$gte = new Date(q.from);
    }
    if (q.to) {
      ensure(!isNaN(Date.parse(q.to)), "Invalid end date");
      f.createdAt.$lte = new Date(q.to);
    }
  }
  if (q.amount) f.amount = money(q.amount);
  return f;
}
app.get(
  "/api/transactions",
  route(async (req, res) => {
    const q = { ...req.query };
    delete q.user;
    const f = transactionFilter(q, req.user.id);
    f.$and = [
      ...(f.$and || []),
      { category: { $ne: "registration_backing" } },
    ];
    res.json({
      items: await M.Transaction.find(f)
        .sort({ createdAt: -1 })
        .skip((page(req.query) - 1) * transactionPageSize)
        .limit(transactionPageSize),
      total: await M.Transaction.countDocuments(f),
      page: page(req.query),
    });
  }),
);
app.get(
  "/api/notifications",
  route(async (req, res) => {
    const notifications = await M.Notification.find({
        $or: [{ user: req.user.id }, { audience: "all" }],
      })
        .sort({ createdAt: -1 })
        .limit(100);
    res.json(
      notifications.map((notification) => {
        const item = notification.toObject(),
          read = notification.readBy.some(
            (userId) => String(userId) === req.user.id,
          );
        delete item.readBy;
        return { ...item, read };
      }),
    );
  }),
);
app.post(
  "/api/notifications/:id/read",
  route(async (req, res) => {
    await M.Notification.updateOne(
      {
        _id: id(req.params.id),
        $or: [{ user: req.user.id }, { audience: "all" }],
      },
      { $addToSet: { readBy: req.user._id } },
    );
    res.json({ message: "Marked as read" });
  }),
);
app.use("/api/admin", admin);
app.get(
  "/api/admin/dashboard",
  route(async (_req, res) => {
    const sum = async (model, match, field = "amount") =>
      (
        await model.aggregate([
          { $match: match },
          { $group: { _id: null, total: { $sum: `$${field}` } } },
        ])
      )[0]?.total || 0;
    const now = new Date(),
      pakistanNow = new Date(now.getTime() + 5 * 60 * 60 * 1000),
      pakistanToday = new Date(pakistanNow);
    pakistanToday.setUTCHours(0, 0, 0, 0);
    const todayStart = new Date(
        pakistanToday.getTime() - 5 * 60 * 60 * 1000,
      ),
      todayEnd = new Date(todayStart.getTime() + 86400000),
      today = { $gte: todayStart, $lt: todayEnd },
      chartStart = new Date(
        pakistanToday.getTime() - 6 * 86400000 - 5 * 60 * 60 * 1000,
      ),
      groupByPakistanDay = {
        $dateToString: {
          format: "%Y-%m-%d",
          date: "$createdAt",
          timezone: "Asia/Karachi",
        },
      },
      dailyCount = async (model, match = {}) =>
        model.aggregate([
          { $match: { ...match, createdAt: { $gte: chartStart } } },
          { $group: { _id: groupByPakistanDay, total: { $sum: 1 } } },
        ]),
      dailyAmount = async (model, match = {}) =>
        model.aggregate([
          { $match: { ...match, createdAt: { $gte: chartStart } } },
          { $group: { _id: groupByPakistanDay, total: { $sum: "$amount" } } },
        ]),
      [registrationRows, depositRows, withdrawalRows] = await Promise.all([
        dailyCount(M.User),
        dailyAmount(M.Deposit, { status: "approved" }),
        dailyAmount(M.Withdrawal, { status: "approved" }),
      ]),
      rowMap = (rows) => new Map(rows.map((row) => [row._id, row.total])),
      registrations = rowMap(registrationRows),
      deposits = rowMap(depositRows),
      withdrawals = rowMap(withdrawalRows),
      activity = Array.from({ length: 7 }, (_, index) => {
        const day = new Date(pakistanToday.getTime() - (6 - index) * 86400000),
          date = day.toISOString().slice(0, 10);
        return {
          date,
          label: day.toLocaleDateString("en-PK", {
            day: "2-digit",
            month: "short",
            timeZone: "UTC",
          }),
          registrations: registrations.get(date) || 0,
          deposits: deposits.get(date) || 0,
          withdrawals: withdrawals.get(date) || 0,
        };
      }),
      liabilities =
      (
        await M.User.aggregate([
          {
            $group: {
              _id: null,
              total: {
                $sum: {
                  $add: [
                    "$wallet.deposit",
                    "$wallet.earned",
                    "$wallet.promo",
                    "$wallet.pending",
                  ],
                },
              },
            },
          },
        ])
      )[0]?.total || 0;
    const [
      todayDeposit,
      todayWithdraw,
      todayInvestment,
      todayJoined,
      totalDeposit,
      totalWithdraw,
      totalInvestment,
      totalEarningsPaid,
      totalExternalRevenue,
    ] = await Promise.all([
      sum(M.Deposit, { status: "approved", createdAt: today }),
      sum(M.Withdrawal, { status: "approved", createdAt: today }),
      sum(M.PlanPurchase, { createdAt: today }, "price"),
      M.User.countDocuments({ createdAt: today }),
      sum(M.Deposit, { status: "approved" }),
      sum(M.Withdrawal, { status: "approved" }),
      sum(M.PlanPurchase, {}, "price"),
      sum(M.Transaction, {
        category: {
          $in: [
            "task_earning",
            "salary_bonus",
            "team_commission",
            "team_task_commission",
          ],
        },
      }),
      sum(M.Revenue, {}),
    ]);
    const platformProfit = totalInvestment + totalExternalRevenue - totalEarningsPaid,
      platformBalance =
        totalDeposit + totalExternalRevenue - totalWithdraw - totalEarningsPaid;
    res.json({
      users: await M.User.countDocuments(),
      activeUsers: await M.User.countDocuments({ status: "active" }),
      activePlans: await M.PlanPurchase.countDocuments({
        expires: { $gt: new Date() },
      }),
      pendingDeposits: await M.Deposit.countDocuments({ status: "pending" }),
      approvedDeposits: await sum(M.Deposit, { status: "approved" }),
      pendingWithdrawals: await M.Withdrawal.countDocuments({
        status: "pending",
      }),
      approvedWithdrawals: await sum(M.Withdrawal, { status: "approved" }),
      taskRewards: await sum(M.Transaction, { category: "task_earning" }),
      commissions: await sum(M.Commission, {}),
      bonuses: await sum(M.Transaction, { category: "salary_bonus" }),
      liabilities,
      today: {
        deposit: todayDeposit,
        withdraw: todayWithdraw,
        investment: todayInvestment,
        joined: todayJoined,
      },
      totals: {
        deposit: totalDeposit,
        withdraw: totalWithdraw,
        earningsPaid: totalEarningsPaid,
        platformProfit,
        platformBalance,
      },
      activity,
    });
  }),
);
app.get(
  "/api/admin/users",
  route(async (req, res) => {
    const f = req.query.search
      ? {
          $or: ["name", "email", "username"].map((k) => ({
            [k]: {
              $regex: text(req.query.search, 1, 80).replace(
                /[.*+?^${}()|[\]\\]/g,
                "\\$&",
              ),
              $options: "i",
            },
          })),
        }
      : {};
    res.json({
      items: await M.User.find(f)
        .select("-sessionVersion")
        .sort({ createdAt: -1 })
        .skip((page(req.query) - 1) * 20)
        .limit(20),
      total: await M.User.countDocuments(f),
    });
  }),
);
app.get(
  "/api/admin/users/:id",
  route(async (req, res) =>
    res.json({
      ...(await snapshot(id(req.params.id))),
      audits: await M.AdminAuditLog.find({ target: req.params.id })
        .sort({ createdAt: -1 })
        .limit(100),
      relationships: await M.ReferralRelationship.findOne({
        user: req.params.id,
      }),
    }),
  ),
);
app.post(
  "/api/admin/users/:id/status",
  route(async (req, res) => {
    const status = z.enum(["active", "suspended"]).parse(req.body.status);
    await atomic(async (s) => {
      const u = await M.User.findById(id(req.params.id)).session(s);
      ensure(u && u.role !== "admin", "Cannot change this account");
      const before = u.status;
      u.status = status;
      u.sessionVersion++;
      await u.save({ session: s });
      await audit(
        req.user.id,
        u.id,
        "account_status",
        text(req.body.reason, 5),
        { status: before },
        { status },
        null,
        s,
      );
    });
    res.json({ message: "Account status updated" });
  }),
);
app.post(
  "/api/admin/users/:id/adjust",
  route(async (req, res) => {
    const amount = money(req.body.amount),
      type = z.enum(["credit", "debit"]).parse(req.body.type),
      reason = text(req.body.reason, 5),
      key = text(req.body.requestId, 8, 100);
    await atomic(async (s) => {
      ensure(
        !(await M.Transaction.exists({ key: `adjust:${key}` }).session(s)),
        "This adjustment has already been processed",
        409,
      );
      const u = await M.User.findById(id(req.params.id)).session(s);
      ensure(u, "User not found", 404);
      const before = JSON.parse(JSON.stringify(u.wallet));
      if (type === "credit")
        await award(u.id, amount, `adjust:${key}`, "adjustment", reason, s);
      else {
        const cuts = take(u.wallet, amount);
        for (const k of Object.keys(cuts)) u.wallet[k] -= cuts[k];
        await u.save({ session: s });
        await ledger(
          u.id,
          `adjust:${key}`,
          "adjustment",
          -amount,
          reason,
          Object.entries(cuts)
            .filter(([, n]) => n)
            .map(([k, n]) => ({ account: `${u.id}:${k}`, amount: -n }))
            .concat({ account: "adjustmentClearing", amount }),
          s,
        );
      }
      const after = JSON.parse(
        JSON.stringify((await M.User.findById(u.id).session(s)).wallet),
      );
      await audit(
        req.user.id,
        u.id,
        "balance_adjustment",
        reason,
        before,
        after,
        key,
        s,
      );
    });
    res.json({ message: "Adjustment recorded" });
  }),
);
app.delete(
  "/api/admin/users/:id",
  route(async (req, res) => {
    const reason = text(req.body.reason, 5),
      confirmation = z.literal("DELETE").parse(req.body.confirmation);
    await atomic(async (s) => {
      const u = await M.User.findById(id(req.params.id)).session(s);
      ensure(u && u.role !== "admin", "Cannot delete this account");
      ensure(u.status !== "deleted", "Account is already deleted", 409);
      const before = {
        name: u.name,
        username: u.username,
        email: u.email,
        status: u.status,
      };
      u.name = "Deleted member";
      u.username = `deleted-${u.id}`;
      u.email = `deleted-${u.id}@deleted.invalid`;
      u.referralCode = `DELETED-${u.id}`;
      u.status = "deleted";
      u.sessionVersion++;
      u.resetHash = undefined;
      u.resetExpires = undefined;
      await u.save({ session: s });
      await M.PayoutAccount.deleteOne({ user: u.id }).session(s);
      await audit(
        req.user.id,
        u.id,
        "account_deleted",
        reason,
        before,
        { status: "deleted" },
        confirmation,
        s,
      );
    });
    res.json({ message: "Account deleted and identifying data removed" });
  }),
);
app.get(
  "/api/admin/deposits",
  route(async (_req, res) =>
    res.json(
      await M.Deposit.find()
        .populate("user", "name email")
        .sort({ createdAt: -1 })
        .limit(200),
    ),
  ),
);
app.get(
  "/api/admin/deposits/:id/proof",
  route(async (req, res) => {
    const d = await M.Deposit.findById(id(req.params.id));
    ensure(d?.file, "Screenshot not found", 404);
    res.sendFile(path.join(uploadDir, d.file));
  }),
);
app.post(
  "/api/admin/deposits/:id/decision",
  route(async (req, res) => {
    const status = z.enum(["approved", "rejected"]).parse(req.body.status),
      reason = text(req.body.reason, 5);
    res.json(
      await atomic(async (s) => {
        const d = await M.Deposit.findById(id(req.params.id)).session(s);
        ensure(
          d?.status === "pending",
          "Deposit has already been processed",
          409,
        );
        if (status === "approved") {
          await M.User.updateOne(
            { _id: d.user },
            { $inc: { "wallet.deposit": d.amount } },
            { session: s },
          );
          await ledger(
            d.user,
            `deposit:${d.id}`,
            "deposit",
            d.amount,
            "Verified deposit approved",
            [
              { account: "paymentClearing", amount: -d.amount },
              { account: `${d.user}:deposit`, amount: d.amount },
            ],
            s,
            d.id,
          );
          await recordSalaryDeposit(d.user, d.amount, s);
          await recordDepositCommissions(d.user, d.amount, d.id, s);
        }
        d.status = status;
        d.reason = reason;
        d.decided = new Date();
        d.decisionBy = req.user.id;
        await d.save({ session: s });
        await audit(
          req.user.id,
          d.user,
          "deposit_" + status,
          reason,
          { status: "pending" },
          { status },
          d.id,
          s,
        );
        await notify(d.user, "Deposit " + status, reason, s);
        return d;
      }),
    );
  }),
);
app.get(
  "/api/admin/withdrawals",
  route(async (_req, res) =>
    res.json(
      (
        await M.Withdrawal.find()
          .populate("user", "name email")
          .sort({ createdAt: -1 })
          .limit(200)
      ).map((w) => ({ ...w.toObject(), account: unseal(w.account.cipher) })),
    ),
  ),
);
app.post(
  "/api/admin/withdrawals/:id/decision",
  route(async (req, res) => {
    const status = z.enum(["approved", "rejected"]).parse(req.body.status),
      reason = text(req.body.reason, 5);
    res.json(
      await atomic(async (s) => {
        const w = await M.Withdrawal.findById(id(req.params.id)).session(s);
        ensure(w?.status === "pending", "Withdrawal has already been processed", 409);
        if (status === "approved") {
          w.paymentRef = `APPROVED-${w.id}`;
          await M.User.updateOne(
            { _id: w.user },
            { $inc: { "wallet.pending": -w.amount } },
            { session: s },
          );
          await ledger(
            w.user,
            `payout:${w.id}`,
            "withdrawal",
            -w.amount,
            "Withdrawal approved and paid",
            [
              { account: `${w.user}:pending`, amount: -w.amount },
              { account: "payoutClearing", amount: w.amount },
            ],
            s,
            w.paymentRef,
          );
        }
        if (status === "rejected") {
          const inc = { "wallet.pending": -w.amount };
          for (const [k, n] of Object.entries(w.reservation))
            inc[`wallet.${k}`] = n;
          await M.User.updateOne(
            { _id: w.user },
            { $inc: inc },
            { session: s },
          );
          await ledger(
            w.user,
            `refund:${w.id}`,
            "withdrawal_release",
            w.amount,
            "Withdrawal rejected, reservation restored",
            [
              { account: `${w.user}:pending`, amount: -w.amount },
              ...Object.entries(w.reservation)
                .filter(([, n]) => n)
                .map(([k, n]) => ({ account: `${w.user}:${k}`, amount: n })),
            ],
            s,
            w.id,
          );
        }
        await audit(
          req.user.id,
          w.user,
          "withdrawal_" + status,
          reason,
          { status: w.status },
          { status },
          w.id,
          s,
        );
        w.status = status;
        w.reason = reason;
        w.decisionBy = req.user.id;
        w.decided = new Date();
        await w.save({ session: s });
        await notify(w.user, "Withdrawal " + status, reason, s);
        return { message: "Withdrawal " + status };
      }),
    );
  }),
);
app.get(
  "/api/admin/promos",
  route(async (_req, res) =>
    res.json(await M.PromoCode.find().sort({ createdAt: -1 })),
  ),
);
app.post(
  "/api/admin/promos",
  route(async (req, res) => {
    const code = text(req.body.code, 2, 40).toUpperCase(),
      budget = money(req.body.budget),
      maxClaims = z
        .number()
        .int()
        .min(1)
        .max(100000)
        .parse(Number(req.body.maxClaims)),
      starts = z.coerce.date().parse(req.body.starts),
      expires = z.coerce.date().parse(req.body.expires);
    ensure(expires > starts, "Expiry must be after start");
    const reward = Math.floor(budget / maxClaims);
    ensure(reward > 0, "Budget is too small");
    const p = await atomic(async (s) => {
      const [p] = await M.PromoCode.create(
        [{ code, budget, maxClaims, reward, starts, expires }],
        { session: s },
      );
      await audit(
        req.user.id,
        null,
        "create_promo",
        "Configured promo reward",
        null,
        { code, budget, maxClaims },
        p.id,
        s,
      );
      return p;
    });
    res.status(201).json(p);
  }),
);
app.patch(
  "/api/admin/promos/:id",
  route(async (req, res) => {
    const active = z.boolean().parse(req.body.active);
    await atomic(async (s) => {
      await M.PromoCode.updateOne(
        { _id: id(req.params.id) },
        { $set: { active } },
        { session: s },
      );
      await audit(
        req.user.id,
        null,
        "promo_status",
        "Promo activation updated",
        null,
        { active },
        req.params.id,
        s,
      );
    });
    res.json({ message: "Promo updated" });
  }),
);
app.get(
  "/api/admin/promos/:id/claims",
  route(async (req, res) =>
    res.json(
      await M.PromoCodeClaim.find({ promo: id(req.params.id) }).populate(
        "user",
        "name email",
      ),
    ),
  ),
);
app.get(
  "/api/admin/payments",
  route(async (_req, res) => res.json(await config("payments", {}))),
);
app.put(
  "/api/admin/payments",
  route(async (req, res) => {
    const val = z
      .record(
        z.enum(["EasyPaisa", "JazzCash", "Mashreq"]),
        z.object({
          title: z.string().max(100),
          number: z.string().max(60),
          bank: z.string().max(100).optional(),
          enabled: z.boolean(),
        }),
      )
      .parse(req.body);
    await atomic(async (s) => {
      const before = await config("payments", {}, s);
      await M.ApplicationConfiguration.updateOne(
        { key: "payments" },
        { $set: { value: val } },
        { upsert: true, session: s },
      );
      await audit(
        req.user.id,
        null,
        "payment_settings",
        "Business account settings updated",
        before,
        val,
        null,
        s,
      );
    });
    res.json({ message: "Payment settings saved" });
  }),
);
app.get(
  "/api/admin/notifications",
  route(async (_req, res) =>
    res.json(
      await M.Notification.find({ audience: "all" })
        .sort({ createdAt: -1 })
        .limit(100),
    ),
  ),
);
app.post(
  "/api/admin/notifications",
  route(async (req, res) => {
    const title = text(req.body.title, 3, 100),
      message = text(req.body.message, 3, 2000),
      audience = z.enum(["all", "user"]).parse(req.body.audience || "all"),
      user = audience === "user" ? id(req.body.user) : undefined;
    await atomic(async (s) => {
      const [n] = await M.Notification.create(
        [{ title, message, audience, user }],
        { session: s },
      );
      await audit(
        req.user.id,
        user,
        "announcement",
        "Announcement created",
        null,
        { title, audience },
        n.id,
        s,
      );
    });
    res.json({ message: "Announcement published" });
  }),
);
app.get(
  "/api/admin/transactions",
  route(async (req, res) => {
    const f = transactionFilter(req.query);
    res.json({
      items: await M.Transaction.find(f)
        .sort({ createdAt: -1 })
        .skip((page(req.query) - 1) * transactionPageSize)
        .limit(transactionPageSize),
      total: await M.Transaction.countDocuments(f),
    });
  }),
);
app.get(
  "/api/admin/audits",
  route(async (req, res) =>
    res.json(
      await M.AdminAuditLog.find(
        req.query.target ? { target: id(req.query.target) } : {},
      )
        .sort({ createdAt: -1 })
        .limit(200),
    ),
  ),
);
app.post(
  "/api/admin/videos",
  upload.single("video"),
  route(async (req, res) => {
    await validateFile(req.file, true);
    const duration = z
        .number()
        .min(5)
        .max(900)
        .parse(Number(req.body.duration)),
      title = text(req.body.title, 3, 100);
    const result = await atomic(async (s) => {
        const existing = await M.Task.find({ title }).session(s);
        const previous = existing.map((task) => task.file).filter(Boolean);
        const tasks = existing.length
          ? existing
          : [
              (
                await M.Task.create(
                  [{ title, duration, file: req.file.filename, mime: "video/mp4" }],
                  { session: s },
                )
              )[0],
            ];
        for (const task of tasks) {
          Object.assign(task, {
            duration,
            file: req.file.filename,
            mime: "video/mp4",
            active: true,
          });
          await task.save({ session: s });
        }
        await audit(
          req.user.id,
          null,
          existing.length ? "replace_video" : "upload_video",
          existing.length ? "Task video replaced" : "Task video uploaded",
          null,
          { title, duration },
          tasks[0].id,
          s,
        );
        return { task: tasks[0], previous };
    });
    for (const previous of new Set(result.previous)) {
        if (previous !== result.task.file)
          await fs.unlink(path.resolve(uploadDir, previous)).catch(() => {});
    }
    res.status(201).json(result.task);
  }),
);
app.delete(
  "/api/admin/videos",
  route(async (req, res) => {
    z.literal("DELETE").parse(req.body.confirmation);
    const tasks = await M.Task.find().select("file");
    const files = [...new Set(tasks.map((task) => task.file).filter(Boolean))];
    const removed = await atomic(async (s) => {
      const assignments = await M.TaskAssignment.deleteMany({}).session(s);
      const result = await M.Task.deleteMany({}).session(s);
      await audit(
        req.user.id,
        null,
        "delete_videos",
        "All task videos deleted",
        null,
        { tasks: result.deletedCount, assignments: assignments.deletedCount },
        null,
        s,
      );
      return { tasks: result.deletedCount, assignments: assignments.deletedCount };
    });
    await Promise.all(
      files.map((file) => fs.unlink(path.resolve(uploadDir, file)).catch(() => {})),
    );
    res.json({ message: "All previous task videos were deleted", ...removed });
  }),
);
app.get(
  "/api/admin/videos",
  route(async (_req, res) =>
    res.json(await M.Task.find().sort({ createdAt: -1 })),
  ),
);
app.post(
  "/api/admin/revenue",
  route(async (req, res) =>
    res
      .status(201)
      .json(
        await recordRevenue(
          req.user.id,
          id(req.body.user),
          money(req.body.amount),
          text(req.body.externalRef, 6, 100),
          text(req.body.reason, 5),
        ),
      ),
  ),
);
app.post(
  "/api/admin/users/:id/impersonate",
  route(async (req, res) => {
    const target = await M.User.findById(id(req.params.id));
    ensure(target && target.role === "user", "User account not found", 404);
    ensure(target.status === "active", "Only active users can be accessed", 409);
    const support = await atomic(async (s) => {
      const [session] = await M.SupportSession.create(
        [
          {
            admin: req.user.id,
            user: target.id,
            reason: "Admin user-account access",
            expires: new Date(Date.now() + 15 * 60000),
          },
        ],
        { session: s },
      );
      await audit(
        req.user.id,
        target.id,
        "impersonation_start",
        "Admin user-account access",
        null,
        null,
        session.id,
        s,
      );
      return session;
    });
    res.json({
      token: signImpersonation(target, req.user, support),
      user: publicUser(target),
      expires: support.expires,
      readOnly: true,
    });
  }),
);
app.post(
  "/api/admin/support-sessions",
  route(async (req, res) => {
    const user = id(req.body.user),
      reason = text(req.body.reason, 5);
    const session = await atomic(async (s) => {
      ensure(
        await M.User.exists({ _id: user }).session(s),
        "User not found",
        404,
      );
      const [v] = await M.SupportSession.create(
        [
          {
            admin: req.user.id,
            user,
            reason,
            expires: new Date(Date.now() + 15 * 60000),
          },
        ],
        { session: s },
      );
      await audit(
        req.user.id,
        user,
        "support_start",
        reason,
        null,
        null,
        v.id,
        s,
      );
      return v;
    });
    res.json(session);
  }),
);
app.get(
  "/api/admin/support-sessions/:id",
  route(async (req, res) => {
    const s = await M.SupportSession.findOne({
      _id: id(req.params.id),
      admin: req.user.id,
      ended: null,
      expires: { $gt: new Date() },
    });
    ensure(s, "Support session ended or expired", 403);
    await audit(
      req.user.id,
      s.user,
      "support_read",
      s.reason,
      null,
      null,
      s.id,
    );
    res.json({
      administrativeAccess: true,
      readOnly: true,
      expires: s.expires,
      ...(await snapshot(s.user)),
    });
  }),
);
app.delete(
  "/api/admin/support-sessions/:id",
  route(async (req, res) => {
    await atomic(async (t) => {
      const s = await M.SupportSession.findOne({
        _id: id(req.params.id),
        admin: req.user.id,
        ended: null,
      }).session(t);
      ensure(s, "Session not found", 404);
      s.ended = new Date();
      await s.save({ session: t });
      await audit(
        req.user.id,
        s.user,
        "support_end",
        s.reason,
        null,
        null,
        s.id,
        t,
      );
    });
    res.json({ message: "Support session ended" });
  }),
);
app.use("/api", (_req, res) =>
  res.status(404).json({ message: "Endpoint not found" }),
);
app.use((err, req, res, _next) => {
  if (req.file) fs.unlink(req.file.path).catch(() => {});
  let status = err.status || 500,
    message =
      status === 500 ? "The operation could not be completed" : err.message;
  if (err instanceof z.ZodError) {
    status = 400;
    message = err.issues
      .map((x) => `${x.path.join(".")}: ${x.message}`)
      .join("; ");
  }
  if (err.code === 11000) {
    status = 409;
    message = err.keyPattern?.email
      ? "An account with this email already exists. Please sign in instead."
      : err.keyPattern?.username
        ? "That username is already in use"
        : "This record has already been processed or the transaction ID is already used";
  }
  if (err instanceof multer.MulterError) {
    status = 400;
    message = "Upload rejected: " + err.message;
  }
  if (status === 500) console.error(err.name, err.message);
  res.status(status).json({ message });
});
