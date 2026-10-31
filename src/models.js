import mongoose from "mongoose";
const { Schema } = mongoose,
  id = Schema.Types.ObjectId;
const ref = (name) => ({ type: id, ref: name, index: true });
const uniqueRef = (name) => ({ type: id, ref: name, unique: true });
const minor = {
  type: Number,
  min: 0,
  default: 0,
  validate: Number.isSafeInteger,
};
function model(name, fields, indexes = []) {
  const s = new Schema(fields, { timestamps: true, strict: "throw" });
  indexes.forEach(([key, opt]) => s.index(key, opt));
  if (["Transaction", "AdminAuditLog"].includes(name)) {
    s.pre("save", function () {
      if (!this.isNew) throw new Error("Ledger is append only");
    });
    for (const op of [
      "updateOne",
      "updateMany",
      "findOneAndUpdate",
      "deleteOne",
      "deleteMany",
      "findOneAndDelete",
      "replaceOne",
    ])
      s.pre(op, function () {
        throw new Error("Ledger is append only");
      });
  }
  return mongoose.model(name, s);
}
export const User = model("User", {
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  status: { type: String, enum: ["active", "suspended"], default: "active" },
  referralCode: { type: String, unique: true },
  referrer: ref("User"),
  ancestors: [id],
  wallet: { deposit: minor, earned: minor, promo: minor, pending: minor },
  purchases: { type: Number, default: 0 },
  promoUnlocked: { type: Boolean, default: false },
  sessionVersion: { type: Number, default: 0 },
  resetHash: { type: String, select: false },
  resetExpires: Date,
});
export const PlanPurchase = model(
  "PlanPurchase",
  {
    user: ref("User"),
    name: String,
    price: minor,
    reward: minor,
    start: Date,
    expires: Date,
    sequence: Number,
    requestKey: String,
  },
  [
    [{ user: 1, sequence: 1 }, { unique: true }],
    [
      { user: 1, requestKey: 1 },
      {
        unique: true,
        partialFilterExpression: { requestKey: { $type: "string" } },
      },
    ],
  ],
);
export const Task = model("Task", {
  title: String,
  file: String,
  mime: String,
  duration: { type: Number, min: 10, max: 900 },
  active: { type: Boolean, default: true },
});
export const TaskAssignment = model(
  "TaskAssignment",
  {
    user: ref("User"),
    purchase: ref("PlanPurchase"),
    task: ref("Task"),
    day: String,
    expires: Date,
    started: Date,
    completed: Date,
    reward: minor,
  },
  [[{ purchase: 1, day: 1 }, { unique: true }]],
);
export const Deposit = model(
  "Deposit",
  {
    user: ref("User"),
    amount: minor,
    method: String,
    tid: String,
    file: String,
    status: {
      type: String,
      enum: ["awaiting", "pending", "expired", "approved", "rejected"],
      default: "awaiting",
    },
    expires: Date,
    reason: String,
    decisionBy: ref("User"),
    decided: Date,
  },
  [
    [
      { method: 1, tid: 1 },
      { unique: true, partialFilterExpression: { tid: { $type: "string" } } },
    ],
  ],
);
export const Withdrawal = model(
  "Withdrawal",
  {
    user: { type: id, ref: "User" },
    amount: minor,
    status: {
      type: String,
      enum: ["pending", "approved", "completed", "rejected"],
      default: "pending",
    },
    account: Object,
    reservation: Object,
    reason: String,
    paymentRef: String,
    decisionBy: ref("User"),
    decided: Date,
  },
  [
    [
      { user: 1 },
      {
        unique: true,
        partialFilterExpression: { status: { $in: ["pending", "approved"] } },
      },
    ],
    [
      { paymentRef: 1 },
      {
        unique: true,
        partialFilterExpression: { paymentRef: { $type: "string" } },
      },
    ],
  ],
);
export const PayoutAccount = model("PayoutAccount", {
  user: uniqueRef("User"),
  cipher: String,
});
export const Transaction = model("Transaction", {
  user: ref("User"),
  key: { type: String, unique: true, required: true },
  category: String,
  amount: Number,
  status: { type: String, default: "completed" },
  description: String,
  reference: String,
  legs: [{ account: String, amount: Number, _id: false }],
});
export const ReferralRelationship = model("ReferralRelationship", {
  user: uniqueRef("User"),
  ancestors: [id],
});
export const Commission = model(
  "Commission",
  {
    user: ref("User"),
    source: ref("User"),
    event: String,
    level: Number,
    amount: minor,
    kind: String,
  },
  [[{ event: 1, user: 1, kind: 1 }, { unique: true }]],
);
export const SalaryBonus = model(
  "SalaryBonus",
  {
    user: ref("User"),
    level: Number,
    qualifiedAt: Date,
    claimAfter: Date,
    claimedAt: Date,
    transaction: ref("Transaction"),
  },
  [[{ user: 1, level: 1 }, { unique: true }]],
);
export const PromoCode = model("PromoCode", {
  code: { type: String, unique: true },
  budget: minor,
  maxClaims: Number,
  reward: minor,
  claims: { type: Number, default: 0 },
  starts: Date,
  expires: Date,
  active: { type: Boolean, default: true },
});
export const PromoCodeClaim = model(
  "PromoCodeClaim",
  { user: ref("User"), promo: ref("PromoCode"), amount: minor },
  [[{ user: 1, promo: 1 }, { unique: true }]],
);
export const Notification = model("Notification", {
  user: ref("User"),
  title: String,
  message: String,
  audience: { type: String, enum: ["all", "user"], default: "user" },
  readBy: [id],
});
export const AdminAuditLog = model("AdminAuditLog", {
  admin: ref("User"),
  target: ref("User"),
  action: String,
  reason: String,
  before: Object,
  after: Object,
  reference: String,
});
export const ApplicationConfiguration = model("ApplicationConfiguration", {
  key: { type: String, unique: true },
  value: Schema.Types.Mixed,
});
export const Revenue = model("Revenue", {
  user: ref("User"),
  amount: minor,
  externalRef: { type: String, unique: true },
  reason: String,
  verifiedBy: ref("User"),
});
export const SupportSession = model("SupportSession", {
  admin: ref("User"),
  user: ref("User"),
  reason: String,
  expires: Date,
  ended: Date,
});
export const Outbox = model("Outbox", {
  user: ref("User"),
  email: String,
  subject: String,
  text: String,
  sent: Date,
  attempts: { type: Number, default: 0 },
});
export const allModels = mongoose.models;
