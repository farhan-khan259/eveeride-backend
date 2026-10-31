import { test, before, after, mock } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import request from "supertest";
import bcrypt from "bcryptjs";
import fs from "node:fs/promises";
import crypto from "node:crypto";
process.env.JWT_SECRET = "test-secret-32-characters-minimum-safe-local-only";
process.env.PAYOUT_ENCRYPTION_KEY = "a".repeat(64);
process.env.TASK_REWARD_MODE = "internal-sponsored";
process.env.UPLOAD_DIR = "/tmp/tron-test-uploads";
const { app } = await import("../src/app.js");
const M = await import("../src/models.js");
const { cfg, hoursOpen, money } = await import("../src/config.js");
const { sign } = await import("../src/security.js");
const { recordRevenue } = await import("../src/finance.js");
let db, admin, adminToken, u, token, second, secondToken;
const api = (t = token) => ({
  get: (p) =>
    request(app)
      .get("/api" + p)
      .auth(t, { type: "bearer" }),
  post: (p, b) =>
    request(app)
      .post("/api" + p)
      .auth(t, { type: "bearer" })
      .send(b),
  put: (p, b) =>
    request(app)
      .put("/api" + p)
      .auth(t, { type: "bearer" })
      .send(b),
});
const fields = (email = "test@example.test", username = "tester") => ({
  name: "Test User",
  username,
  email,
  password: "SecureTest123",
  confirmPassword: "SecureTest123",
  terms: true,
});
before(
  async () => {
    db = await MongoMemoryReplSet.create({
      replSet: { count: 1 },
      binary: { version: "7.0.24" },
    });
    await mongoose.connect(db.getUri());
    await Promise.all(Object.values(M.allModels).map((m) => m.init()));
    admin = await M.User.create({
      name: "Admin",
      username: "admin",
      email: "admin@example.test",
      password: await bcrypt.hash("AdminSecure123", 4),
      role: "admin",
      referralCode: "ADMINREF",
      wallet: { deposit: 0, earned: 0, promo: 0, pending: 0 },
    });
    adminToken = sign(admin);
    mock.timers.enable({
      apis: ["Date"],
      now: new Date("2026-10-31T06:00:00Z"),
    });
    cfg.live = true;
    cfg.funding = "TEST-BUSINESS-SPONSOR-POLICY";
    await M.ApplicationConfiguration.create({
      key: "rewardFund",
      value: { available: 10000000 },
    });
    await M.ApplicationConfiguration.create({
      key: "payments",
      value: {
        EasyPaisa: {
          title: "TEST ACCOUNT ONLY",
          number: "03000000000",
          enabled: true,
        },
      },
    });
  },
  { timeout: 180000 },
);
after(async () => {
  mock.timers.reset();
  await mongoose.disconnect();
  await db?.stop();
  await fs.rm("/tmp/tron-test-uploads", { recursive: true, force: true });
});
test("decimal-safe money and Pakistan operating-hour boundaries", () => {
  assert.equal(money("42.50"), 4250);
  assert.throws(() => money("1.001"));
  assert.throws(() => money("-5"));
  assert.equal(hoursOpen(new Date("2026-10-31T02:59:59Z")), false);
  assert.equal(hoursOpen(new Date("2026-10-31T03:00:00Z")), true);
  assert.equal(hoursOpen(new Date("2026-10-31T11:59:59Z")), true);
  assert.equal(hoursOpen(new Date("2026-10-31T12:00:00Z")), false);
});
test("registration creates one locked Rs20 bonus and balanced ledger", async () => {
  const r = await request(app).post("/api/auth/register").send(fields());
  assert.equal(r.status, 201, r.text);
  token = r.body.token;
  u = await M.User.findById(r.body.user.id);
  assert.equal(u.wallet.promo, 2000);
  assert.equal(u.wallet.earned, 0);
  const t = await M.Transaction.findOne({ user: u.id });
  assert.equal(
    t.legs.reduce((n, l) => n + l.amount, 0),
    0,
  );
  assert.equal(
    await M.Transaction.countDocuments({ key: `registration:${u.id}` }),
    1,
  );
});
test("duplicate email is rejected without another bonus", async () => {
  const r = await request(app)
    .post("/api/auth/register")
    .send(fields("test@example.test", "another"));
  assert.equal(r.status, 409, r.text);
  assert.equal(await M.User.countDocuments({ email: "test@example.test" }), 1);
});
test("invalid referral code fails and valid referral creates ancestors", async () => {
  const invalid = await request(app)
    .post("/api/auth/register")
    .send({
      ...fields("invalid@example.test", "invalid"),
      referralCode: "NOPE",
    });
  assert.equal(invalid.status, 400, invalid.text);
  const r = await request(app)
    .post("/api/auth/register")
    .send({
      ...fields("second@example.test", "second"),
      referralCode: u.referralCode,
    });
  assert.equal(r.status, 201, r.text);
  second = await M.User.findById(r.body.user.id);
  secondToken = r.body.token;
  assert.equal(String(second.ancestors[0]), u.id);
});
test("login validates password and hashes are never returned", async () => {
  let r = await request(app)
    .post("/api/auth/login")
    .send({ email: u.email, password: "incorrect" });
  assert.equal(r.status, 401);
  r = await request(app)
    .post("/api/auth/login")
    .send({ email: u.email, password: "SecureTest123" });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.user.password, undefined);
});
test("password reset is generic, hashed, single-use and revokes sessions", async () => {
  const r = await request(app)
    .post("/api/auth/forgot")
    .send({ email: second.email });
  assert.equal(r.status, 200);
  const unknown = await request(app)
    .post("/api/auth/forgot")
    .send({ email: "unknown@example.test" });
  assert.deepEqual(r.body, unknown.body);
  const mail = await M.Outbox.findOne({
    user: second.id,
    subject: "Reset your password",
  });
  const raw = mail.text.split("token=")[1];
  const saved = await M.User.findById(second.id).select("+resetHash");
  assert.notEqual(saved.resetHash, raw);
  const reset = await request(app)
    .post("/api/auth/reset")
    .send({ token: raw, password: "ChangedSecure123" });
  assert.equal(reset.status, 200, reset.text);
  assert.equal((await api(secondToken).get("/me")).status, 401);
  assert.equal(
    (
      await request(app)
        .post("/api/auth/reset")
        .send({ token: raw, password: "ChangedSecure123" })
    ).status,
    400,
  );
});
test("non-admin cannot read admin records or another user ledger", async () => {
  assert.equal((await api().get("/admin/users")).status, 403);
  const r = await api().get("/transactions?user=" + admin.id);
  assert.equal(r.status, 200, r.text);
  assert.ok(r.body.items.every((x) => x.user === u.id));
});
test("registration bonus is nonwithdrawable and active paid plan is mandatory", async () => {
  const d = await api().get("/dashboard");
  assert.equal(d.body.available, 2000);
  assert.equal(d.body.withdrawable, 0);
  assert.equal(
    (await api().post("/withdrawals", { amount: "100" })).status,
    400,
  );
});
test("deposits reject amounts below 510 and remain pending until approval", async () => {
  assert.equal(
    (
      await api().post("/deposits/order", {
        amount: "509",
        method: "EasyPaisa",
      })
    ).status,
    400,
  );
  const r = await api().post("/deposits/order", {
    amount: "2000",
    method: "EasyPaisa",
  });
  assert.equal(r.status, 201, r.text);
  const png = Buffer.from("89504e470d0a1a0a00000000", "hex");
  const submit = await request(app)
    .post(`/api/deposits/${r.body.order._id}/submit`)
    .auth(token, { type: "bearer" })
    .field("tid", "TEST-TID-001")
    .attach("screenshot", png, {
      filename: "proof.png",
      contentType: "image/png",
    });
  assert.equal(submit.status, 200, submit.text);
  assert.equal(submit.body.status, "pending");
  assert.equal((await M.User.findById(u.id)).wallet.deposit, 0);
});
test("deposit approval credits once under competing requests and is audited", async () => {
  const d = await M.Deposit.findOne({ user: u.id, status: "pending" });
  const results = await Promise.all([
    api(adminToken).post(`/admin/deposits/${d.id}/decision`, {
      status: "approved",
      reason: "Verified externally test payment",
    }),
    api(adminToken).post(`/admin/deposits/${d.id}/decision`, {
      status: "approved",
      reason: "Verified externally test payment",
    }),
  ]);
  assert.deepEqual(results.map((x) => x.status).sort(), [200, 409]);
  assert.equal((await M.User.findById(u.id)).wallet.deposit, 200000);
  assert.equal(
    await M.Transaction.countDocuments({ key: `deposit:${d.id}` }),
    1,
  );
  assert.equal(await M.AdminAuditLog.countDocuments({ reference: d.id }), 1);
});
test("duplicate deposit TID cannot be submitted again", async () => {
  const r = await api().post("/deposits/order", {
    amount: "510",
    method: "EasyPaisa",
  });
  const result = await request(app)
    .post(`/api/deposits/${r.body.order._id}/submit`)
    .auth(token, { type: "bearer" })
    .field("tid", "TEST-TID-001")
    .attach("screenshot", Buffer.from("89504e470d0a1a0a", "hex"), {
      filename: "proof.png",
      contentType: "image/png",
    });
  assert.equal(result.status, 409, result.text);
});
test("Starter purchases enforce three lifetime purchases atomically", async () => {
  await M.ApplicationConfiguration.updateOne(
    { key: "rewardFund" },
    { $set: { "value.available": 0 } },
  );
  for (let i = 0; i < 3; i++) {
    const r = await api().post("/plans/purchase", {
      requestId: crypto.randomUUID(),
    });
    assert.equal(r.status, 201, r.text);
  }
  const fourth = await api().post("/plans/purchase", {
    requestId: crypto.randomUUID(),
  });
  assert.equal(fourth.status, 409, fourth.text);
  assert.equal(await M.PlanPurchase.countDocuments({ user: u.id }), 3);
  assert.equal((await M.User.findById(u.id)).wallet.deposit, 47000);
  assert.equal((await M.User.findById(u.id)).promoUnlocked, true);
  await M.ApplicationConfiguration.updateOne(
    { key: "rewardFund" },
    { $set: { "value.available": 10000000 } },
  );
});
test("payout account binding requires password; details are encrypted at rest", async () => {
  const b = {
    holder: "Test User",
    type: "EasyPaisa",
    number: "03000000000",
    password: "wrong",
  };
  assert.equal((await api().put("/payout-account", b)).status, 403);
  b.password = "SecureTest123";
  const r = await api().put("/payout-account", b);
  assert.equal(r.status, 200, r.text);
  const saved = await M.PayoutAccount.findOne({ user: u.id });
  assert.ok(!saved.cipher.includes(b.number));
  assert.equal((await api().get("/payout-account")).body.number, b.number);
});
test("withdrawals enforce minimum and reserve only one pending amount", async () => {
  assert.equal(
    (await api().post("/withdrawals", { amount: "99" })).status,
    400,
  );
  const results = await Promise.all([
    api().post("/withdrawals", { amount: "100" }),
    api().post("/withdrawals", { amount: "100" }),
  ]);
  assert.deepEqual(results.map((x) => x.status).sort(), [201, 400]);
  const saved = await M.User.findById(u.id);
  assert.equal(saved.wallet.pending, 10000);
  assert.equal(saved.wallet.deposit, 37000);
});
test("withdrawal rejection restores the exact reserved funds once", async () => {
  const w = await M.Withdrawal.findOne({ user: u.id, status: "pending" });
  let r = await api(adminToken).post(`/admin/withdrawals/${w.id}/decision`, {
    status: "rejected",
    reason: "Test payout rejection and restore",
  });
  assert.equal(r.status, 200, r.text);
  const saved = await M.User.findById(u.id);
  assert.equal(saved.wallet.pending, 0);
  assert.equal(saved.wallet.deposit, 47000);
  r = await api(adminToken).post(`/admin/withdrawals/${w.id}/decision`, {
    status: "rejected",
    reason: "Test duplicate rejection",
  });
  assert.equal(r.status, 409);
});
test("withdrawal approval does not mark paid; completion needs external reference", async () => {
  const r = await api().post("/withdrawals", { amount: "100" }),
    w = { _id: r.body.id };
  assert.equal(r.status, 201, r.text);
  assert.equal(
    (
      await api(adminToken).post(`/admin/withdrawals/${w._id}/decision`, {
        status: "completed",
        reason: "Invalid direct completion",
        paymentRef: "PAY-TEST-1",
      })
    ).status,
    409,
  );
  assert.equal(
    (
      await api(adminToken).post(`/admin/withdrawals/${w._id}/decision`, {
        status: "approved",
        reason: "Payout account verified",
      })
    ).status,
    200,
  );
  assert.equal((await M.User.findById(u.id)).wallet.pending, 10000);
  assert.equal(
    (
      await api(adminToken).post(`/admin/withdrawals/${w._id}/decision`, {
        status: "completed",
        reason: "Actual payment test reference",
        paymentRef: "PAY-TEST-1",
      })
    ).status,
    200,
  );
  assert.equal((await M.User.findById(u.id)).wallet.pending, 0);
});
test("task completion enforces server duration and exactly one reward", async () => {
  const task = await M.Task.create({
    title: "Internal sponsored test",
    duration: 10,
    file: "test.mp4",
  });
  let r = await api().get("/tasks");
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.length, 3);
  const id = r.body[0]._id;
  assert.equal((await api().post(`/tasks/${id}/complete`, {})).status, 400);
  assert.equal((await api().post(`/tasks/${id}/start`, {})).status, 200);
  assert.equal((await api().post(`/tasks/${id}/complete`, {})).status, 400);
  await M.TaskAssignment.updateOne(
    { _id: id },
    { $set: { started: new Date(Date.now() - 11000) } },
  );
  const result = await Promise.all([
    api().post(`/tasks/${id}/complete`, {}),
    api().post(`/tasks/${id}/complete`, {}),
  ]);
  assert.deepEqual(result.map((x) => x.status).sort(), [200, 409]);
  assert.equal(await M.Transaction.countDocuments({ key: `task:${id}` }), 1);
  assert.equal((await M.User.findById(u.id)).wallet.earned, 4250);
});
test("expired plans do not generate new assignments or allow completion", async () => {
  const p = await M.PlanPurchase.findOne({ user: u.id });
  await M.PlanPurchase.updateOne(
    { _id: p.id },
    { $set: { expires: new Date(Date.now() - 1000) } },
  );
  const a = await M.TaskAssignment.findOne({ purchase: p.id });
  await M.TaskAssignment.updateOne(
    { _id: a.id },
    { $set: { started: new Date(Date.now() - 20000), completed: null } },
  );
  assert.equal((await api().post(`/tasks/${a.id}/start`, {})).status, 400);
  assert.equal((await api().post(`/tasks/${a.id}/complete`, {})).status, 400);
  assert.equal((await api().get("/dashboard")).body.activePlans.length, 2);
});
test("promo claims enforce one per user and atomic capacity", async () => {
  let r = await api(adminToken).post("/admin/promos", {
    code: "TESTPROMO",
    budget: "100",
    maxClaims: 50,
    starts: new Date(Date.now() - 10000).toISOString(),
    expires: new Date(Date.now() + 86400000).toISOString(),
  });
  assert.equal(r.status, 201, r.text);
  assert.equal(r.body.reward, 200);
  const result = await Promise.all([
    api().post("/promos/claim", { code: "TESTPROMO" }),
    api().post("/promos/claim", { code: "TESTPROMO" }),
  ]);
  assert.deepEqual(result.map((x) => x.status).sort(), [200, 409]);
  assert.equal((await M.PromoCode.findOne({ code: "TESTPROMO" })).claims, 1);
  await M.PromoCode.updateOne({ code: "TESTPROMO" }, { $set: { claims: 50 } });
  assert.equal(
    (await api().post("/promos/claim", { code: "TESTPROMO" })).status,
    400,
  );
});
test("deposits never qualify team targets; verified revenue starts independent ten-day timers", async () => {
  assert.equal((await api().get("/salary")).body.total, 0);
  const r = await recordRevenue(
    admin.id,
    second.id,
    1000000,
    "REV-TEST-001",
    "Verified real business activity test",
  );
  const states = await M.SalaryBonus.find({ user: u.id }).sort({ level: 1 });
  assert.equal(states.length, 2);
  assert.equal(+states[0].claimAfter - +states[0].qualifiedAt, 864000000);
  assert.equal((await api().post("/salary/1/claim", {})).status, 400);
  assert.equal(await M.Commission.countDocuments(), 0);
});
test("bonus claim requires approved policy, elapsed ten days, funds; claims only once", async () => {
  await M.ApplicationConfiguration.create({
    key: "bonusPolicy",
    value: { enabled: true, reference: "test-approved-business-budget" },
  });
  await M.SalaryBonus.updateOne(
    { user: u.id, level: 1 },
    { $set: { claimAfter: new Date(Date.now() - 1000) } },
  );
  const result = await Promise.all([
    api().post("/salary/1/claim", {}),
    api().post("/salary/1/claim", {}),
  ]);
  assert.deepEqual(result.map((x) => x.status).sort(), [200, 409]);
  assert.equal(
    await M.Transaction.countDocuments({
      user: u.id,
      category: "salary_bonus",
    }),
    1,
  );
});
test("manual adjustments are funded, idempotent, nonnegative and audited", async () => {
  const payload = {
    amount: "10",
    type: "credit",
    reason: "Test funded manual adjustment",
    requestId: "ADJUST-TEST-001",
  };
  let r = await api(adminToken).post(`/admin/users/${u.id}/adjust`, payload);
  assert.equal(r.status, 200, r.text);
  r = await api(adminToken).post(`/admin/users/${u.id}/adjust`, payload);
  assert.equal(r.status, 409);
  assert.equal(
    await M.AdminAuditLog.countDocuments({ reference: payload.requestId }),
    1,
  );
  r = await api(adminToken).post(`/admin/users/${u.id}/adjust`, {
    ...payload,
    type: "debit",
    amount: "10000000",
    requestId: "ADJUST-TEST-002",
  });
  assert.equal(r.status, 409);
});
test("all financial ledger events balance and cannot be updated", async () => {
  for (const t of await M.Transaction.find())
    assert.equal(
      t.legs.reduce((n, l) => n + l.amount, 0),
      0,
      t.key,
    );
  await assert.rejects(
    () => M.Transaction.updateOne({ user: u.id }, { $set: { amount: 1 } }),
    /append only/,
  );
});
test("audited support session is scoped read-only and explicitly terminates", async () => {
  let r = await api(adminToken).post("/admin/support-sessions", {
    user: u.id,
    reason: "Troubleshoot account dashboard",
  });
  assert.equal(r.status, 200, r.text);
  const id = r.body._id;
  r = await api(adminToken).get("/admin/support-sessions/" + id);
  assert.equal(r.body.readOnly, true);
  assert.equal(r.body.administrativeAccess, true);
  r = await request(app)
    .delete("/api/admin/support-sessions/" + id)
    .auth(adminToken, { type: "bearer" });
  assert.equal(r.status, 200, r.text);
  assert.equal(
    (await api(adminToken).get("/admin/support-sessions/" + id)).status,
    403,
  );
  assert.equal(await M.AdminAuditLog.countDocuments({ reference: id }), 3);
});
test("admin impersonation logs in read-only without exposing user credentials", async () => {
  const r = await api(adminToken).post(`/admin/users/${u.id}/impersonate`, {});
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.user.id, u.id);
  assert.equal(r.body.readOnly, true);
  assert.ok(r.body.token);
  assert.equal((await api(r.body.token).get("/dashboard")).status, 200);
  assert.equal(
    (
      await api(r.body.token).post("/plans/purchase", {
        requestId: crypto.randomUUID(),
      })
    ).status,
    403,
  );
  assert.equal(
    await M.AdminAuditLog.countDocuments({
      admin: admin.id,
      target: u.id,
      action: "impersonation_start",
    }),
    1,
  );
});
test("suspension revokes user sessions and retains financial history", async () => {
  const n = await M.Transaction.countDocuments({ user: u.id });
  const r = await api(adminToken).post(`/admin/users/${u.id}/status`, {
    status: "suspended",
    reason: "Test suspension for security review",
  });
  assert.equal(r.status, 200, r.text);
  assert.equal((await api().get("/dashboard")).status, 401);
  assert.equal(await M.Transaction.countDocuments({ user: u.id }), n);
});
