import nodemailer from "nodemailer";
import { Deposit, Outbox, TaskAssignment } from "./models.js";
let running = false;

async function sendWithBrevo(item) {
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": process.env.BREVO_API_KEY,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: {
        email: process.env.BREVO_FROM_EMAIL,
        name: process.env.BREVO_FROM_NAME || "EveeRide",
      },
      to: [{ email: item.email }],
      subject: item.subject,
      textContent: item.text,
    }),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Brevo returned ${response.status}: ${detail}`);
  }
}

export async function runJobs() {
  if (running) return;
  running = true;
  try {
    await Deposit.updateMany(
      { status: "awaiting", expires: { $lt: new Date() } },
      { $set: { status: "expired" } },
    );
    const useBrevo = Boolean(
      process.env.BREVO_API_KEY && process.env.BREVO_FROM_EMAIL,
    );
    if (!useBrevo && !process.env.SMTP_HOST) return;
    const smtp = useBrevo
      ? null
      : nodemailer.createTransport({
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
        if (useBrevo) {
          await sendWithBrevo(item);
        } else {
          await smtp.sendMail({
            from: process.env.SMTP_FROM,
            to: item.email,
            subject: item.subject,
            text: item.text,
          });
        }
        await Outbox.updateOne(
          { _id: item.id },
          { $set: { sent: new Date(), text: "[delivered]" } },
        );
      } catch (e) {
        console.error("Email delivery failed", e.message);
      }
    }
  } finally {
    running = false;
  }
}
