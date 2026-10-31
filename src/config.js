import "dotenv/config";
export const cfg = {
  port: Number(process.env.PORT || 4000),
  mongo:
    process.env.MONGODB_URI ||
    process.env.MONGODB_URL ||
    "mongodb://127.0.0.1:27017/tron?replicaSet=rs0",
  secret: process.env.JWT_SECRET,
  web: process.env.WEB_URL || "http://localhost:5173",
  origins: (
    process.env.CORS_ORIGINS || "http://localhost:5173,https://localhost"
  ).split(","),
  live: process.env.PAYMENTS_ENABLED === "true",
  support: process.env.SUPPORT_EMAIL || "",
  business:
    process.env.BUSINESS_NAME || "Business identity pending configuration",
};
export const PLAN = {
  name: "EVEERIDE — STARTER PLAN",
  price: 51000,
  reward: 4250,
  dailyTasks: 1,
  days: 28,
  maxPurchases: 3,
};
export const LEVELS = [
  [500000, 50000],
  [1000000, 100000],
  [2000000, 150000],
  [3000000, 200000],
  [4000000, 250000],
  [5000000, 300000],
  [6000000, 350000],
  [7000000, 400000],
  [8500000, 450000],
  [10000000, 500000],
];
export class Fault extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}
export const ensure = (condition, message, status = 400) => {
  if (!condition) throw new Fault(message, status);
};
export function hoursOpen(now = new Date()) {
  const h = Number(
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Karachi",
      hour: "2-digit",
      hourCycle: "h23",
    }).format(now),
  );
  return h >= 8 && h < 17;
}
export function money(value) {
  ensure(
    typeof value === "string" || typeof value === "number",
    "Invalid amount",
  );
  const s = String(value);
  ensure(
    /^\d+(\.\d{1,2})?$/.test(s),
    "Use a positive amount with at most two decimals",
  );
  const [a, b = ""] = s.split(".");
  const n = Number(a) * 100 + Number(b.padEnd(2, "0"));
  ensure(
    Number.isSafeInteger(n) && n > 0 && n <= 10000000000,
    "Invalid amount",
  );
  return n;
}
export const dayKey = (now = new Date()) =>
  new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Karachi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(now);
