import mongoose from "mongoose";
import { cfg, ensure } from "./config.js";
import { User, ApplicationConfiguration } from "./models.js";
import { atomic, audit } from "./finance.js";
// Operator-only CLI. No endpoint or admin navigation is added.
const [key, reference, mode = "disabled"] = process.argv.slice(2);
ensure(
  ["referralPolicy", "bonusPolicy"].includes(key),
  "Use referralPolicy or bonusPolicy",
);
ensure(reference?.length >= 5, "Supply a documented business-policy reference");
ensure(
  ["enabled", "disabled", "enabled-with-task-referrals"].includes(mode),
  "Invalid policy mode",
);
await mongoose.connect(cfg.mongo);
const admin = await User.findOne({ role: "admin" });
ensure(admin, "Initialize Super Admin first");
await atomic(async (session) => {
  const before = (
    await ApplicationConfiguration.findOne({ key }).session(session)
  )?.value;
  const value = {
    enabled: mode !== "disabled",
    reference,
    taskEnabled: mode === "enabled-with-task-referrals",
  };
  await ApplicationConfiguration.updateOne(
    { key },
    { $set: { value } },
    { upsert: true, session },
  );
  await audit(
    admin.id,
    null,
    "configure_reward_policy",
    reference,
    before,
    value,
    key,
    session,
  );
});
console.log("Policy configuration saved with an audit record.");
await mongoose.disconnect();
