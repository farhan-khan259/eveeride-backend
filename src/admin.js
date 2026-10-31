import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import { cfg, ensure } from "./config.js";
import { User } from "./models.js";
ensure(
  process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD?.length >= 12,
  "Set ADMIN_EMAIL and a strong ADMIN_PASSWORD",
);
await mongoose.connect(cfg.mongo);
ensure(!(await User.exists({ role: "admin" })), "A Super Admin already exists");
await User.create({
  name: "Super Admin",
  username: "superadmin",
  email: process.env.ADMIN_EMAIL.toLowerCase(),
  password: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12),
  role: "admin",
  referralCode: crypto.randomBytes(6).toString("hex").toUpperCase(),
  wallet: { deposit: 0, earned: 0, promo: 0, pending: 0 },
});
console.log(
  "Super Admin created. Remove bootstrap credentials from your environment.",
);
await mongoose.disconnect();
