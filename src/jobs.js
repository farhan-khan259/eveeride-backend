import nodemailer from "nodemailer";
import { Deposit, Outbox, TaskAssignment } from "./models.js";
let running = false;
export async function runJobs() {
  if (running) return;
  running = true;
  try {
    await Deposit.updateMany(
      { status: "awaiting", expires: { $lt: new Date() } },
      { $set: { status: "expired" } },
    );
    if (!process.env.SMTP_HOST) return;
    const smtp = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    });
    for (const item of await Outbox.find({
      sent: null,
      attempts: { $lt: 10 },
    }).limit(30)) {
      await Outbox.updateOne({ _id: item.id }, { $inc: { attempts: 1 } });
      try {
        await smtp.sendMail({
          from: process.env.SMTP_FROM,
          to: item.email,
          subject: item.subject,
          text: item.text,
        });
        await Outbox.updateOne(
          { _id: item.id },
          { $set: { sent: new Date(), text: "[delivered]" } },
        );
      } catch (e) {
        console.error("Email delivery failed", e.code);
      }
    }
  } finally {
    running = false;
  }
}
