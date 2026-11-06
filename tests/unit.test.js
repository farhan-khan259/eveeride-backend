import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
process.env.JWT_SECRET = "unit-test-secret-with-more-than-32-characters";
process.env.PAYOUT_ENCRYPTION_KEY = "a".repeat(64);
const {
  money,
  hoursOpen,
  PLAN,
  LEVELS,
  DEPOSIT_COMMISSION_RATES,
  TEAM_EARNING_COMMISSION_RATE,
} = await import("../src/config.js");
const { take } = await import("../src/finance.js");
const { seal, unseal, hash, sign } = await import("../src/security.js");
const M = await import("../src/models.js");
const { app } = await import("../src/app.js");
const { default: request } = await import("supertest");
test("money converts exact decimal values into integer paisa", () => {
  assert.equal(money("42.50"), 4250);
  assert.equal(money("510"), 51000);
  assert.equal(money("0.01"), 1);
});
test("money rejects invalid precision, negatives, notation and excessive values", () => {
  for (const v of [
    "1.001",
    "-1",
    "0",
    "1e5",
    "Infinity",
    "abc",
    "999999999999999",
  ])
    assert.throws(() => money(v));
});
test("operating hours include 08:00 and exclude 17:00 Pakistan time", () => {
  for (const [d, expected] of [
    ["2026-10-31T02:59:59Z", false],
    ["2026-10-31T03:00:00Z", true],
    ["2026-10-31T11:59:59Z", true],
    ["2026-10-31T12:00:00Z", false],
  ])
    assert.equal(hoursOpen(new Date(d)), expected);
});
test("withdrawal reservations preserve exact source bucket allocation", () => {
  const wallet = { deposit: 4000, earned: 5000, promo: 2000 };
  assert.deepEqual(take(wallet, 10000), {
    deposit: 4000,
    earned: 5000,
    promo: 1000,
  });
  assert.deepEqual(wallet, { deposit: 4000, earned: 5000, promo: 2000 });
});
test("locked promotional balance cannot cover a funded purchase", () => {
  assert.throws(
    () => take({ deposit: 1000, earned: 0, promo: 2000 }, 2000, false),
    /Insufficient/,
  );
});
test("insufficient balance is rejected without changing buckets", () => {
  const w = { deposit: 0, earned: 0, promo: 2000 };
  assert.throws(() => take(w, 3000), /Insufficient/);
  assert.equal(w.promo, 2000);
});
test("payout details round-trip encrypted and reject tampering", () => {
  const value = { holder: "Example", number: "03000000000" },
    cipher = seal(value);
  assert.deepEqual(unseal(cipher), value);
  assert.ok(!cipher.includes(value.number));
  const chunks = cipher.split(":");
  chunks[2] = "00" + chunks[2].slice(2);
  assert.throws(() => unseal(chunks.join(":")));
});
test("reset hashes are deterministic and do not store raw token", () => {
  const token = crypto.randomBytes(32).toString("hex");
  assert.equal(hash(token).length, 64);
  assert.notEqual(hash(token), token);
  assert.equal(hash(token), hash(token));
});
test("financial models have unique processing constraints", () => {
  for (const name of [
    "Transaction",
    "Deposit",
    "Withdrawal",
    "PromoCodeClaim",
    "SalaryBonus",
    "TaskAssignment",
  ])
    assert.ok(
      M[name].schema.indexes().some(([, opts]) => opts.unique),
      name,
    );
});
test("invalid negative financial balances fail schema validation", () => {
  const u = new M.User({
    name: "Example",
    email: "x@example.test",
    username: "example",
    password: "hash",
    wallet: { deposit: -1 },
  });
  assert.ok(u.validateSync()?.errors["wallet.deposit"]);
});
test("ledger and audits reject query mutation before any database operation", async () => {
  await assert.rejects(
    () => M.Transaction.updateOne({}, { $set: { amount: 1 } }),
    /append only/,
  );
  await assert.rejects(() => M.AdminAuditLog.deleteMany({}), /append only/);
});
test("fixed plan and ten one-time levels preserve requested amounts", () => {
  assert.equal(PLAN.reward, 3400);
  assert.equal(PLAN.dailyTasks, 1);
  assert.equal(PLAN.days, 35);
  assert.equal(PLAN.reward * PLAN.dailyTasks * PLAN.days, 119000);
  assert.equal(PLAN.price, 51000);
  assert.equal(PLAN.maxPurchases, 3);
  assert.equal(LEVELS.length, 10);
  assert.deepEqual(LEVELS[9], [10000000, 500000]);
});
test("commission rates match the published deposit and team earning policy", () => {
  assert.deepEqual(DEPOSIT_COMMISSION_RATES, [7, 3, 2, 2]);
  assert.equal(TEAM_EARNING_COMMISSION_RATE, 4);
});
test("protected routes reject unauthenticated requests without database access", async () => {
  for (const endpoint of ["/me", "/admin/dashboard", "/transactions"])
    assert.equal((await request(app).get("/api" + endpoint)).status, 401);
});
test("registration input rejects missing consent and weak password before writes", async () => {
  const r = await request(app)
    .post("/api/auth/register")
    .send({
      name: "Example",
      username: "user",
      email: "test@example.test",
      password: "weak",
      confirmPassword: "weak",
      terms: false,
    });
  assert.equal(r.status, 400);
  assert.match(r.body.message, /password|terms/);
});
test("health accurately reports missing database", async () => {
  const r = await request(app).get("/api/health");
  assert.equal(r.body.status, "database-unavailable");
});
