import mongoose from "mongoose";
import { cfg } from "./config.js";
import { User, Transaction } from "./models.js";
await mongoose.connect(cfg.mongo);
let issues = 0,
  events = 0;
const totals = new Map();
for await (const t of Transaction.find().cursor()) {
  events++;
  if (t.legs.reduce((a, l) => a + l.amount, 0) !== 0) {
    console.error("Unbalanced event", t.id);
    issues++;
  }
  for (const l of t.legs)
    totals.set(l.account, (totals.get(l.account) || 0) + l.amount);
}
for await (const u of User.find().cursor())
  for (const k of ["deposit", "earned", "promo", "pending"]) {
    const sum = totals.get(`${u.id}:${k}`) || 0;
    if (sum !== u.wallet[k]) {
      console.error("Wallet reconciliation mismatch", {
        user: u.id,
        bucket: k,
        ledger: sum,
        wallet: u.wallet[k],
      });
      issues++;
    }
  }
console.log(
  JSON.stringify({ events, issues, status: issues ? "mismatch" : "balanced" }),
);
await mongoose.disconnect();
process.exitCode = issues ? 1 : 0;
