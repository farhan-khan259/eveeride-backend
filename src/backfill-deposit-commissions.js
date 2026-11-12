import mongoose from "mongoose";
import "dotenv/config";
import * as M from "./models.js";
import { cfg } from "./config.js";
import { atomic, audit, recordDepositCommissions } from "./finance.js";

await mongoose.connect(cfg.mongo);
try {
  const admin = await M.User.findOne({ role: "admin" });
  if (!admin) throw new Error("No admin user found");

  const deposits = await M.Deposit.find({ status: "approved" })
    .select("user amount _id decided updatedAt createdAt")
    .sort({ createdAt: 1 });
  let processed = 0;
  let credited = 0;

  for (const deposit of deposits) {
    const result = await atomic(async (session) => {
      const before = await M.Commission.countDocuments({
        event: String(deposit._id),
        kind: "deposit",
      }).session(session);
      await recordDepositCommissions(
        deposit.user,
        deposit.amount,
        deposit._id,
        session,
        deposit.decided || deposit.updatedAt || deposit.createdAt,
      );
      const after = await M.Commission.countDocuments({
        event: String(deposit._id),
        kind: "deposit",
      }).session(session);
      return after - before;
    });
    processed++;
    credited += result;
  }

  await atomic((session) =>
    audit(
      admin.id,
      null,
      "backfill_deposit_commissions",
      "Reconciled missing commissions using deposit approval-time eligibility",
      null,
      { depositsProcessed: processed, commissionsCredited: credited },
      "approved-deposit-commission-backfill",
      session,
    ),
  );
  console.log(
    `Backfill complete: ${processed} approved deposits checked, ${credited} commissions credited.`,
  );
} finally {
  await mongoose.disconnect();
}
