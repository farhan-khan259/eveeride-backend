import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { cfg, ensure } from "./config.js";
import { User, SupportSession, AdminAuditLog } from "./models.js";
export function sign(user) {
  return jwt.sign({ sub: user.id, version: user.sessionVersion }, cfg.secret, {
    expiresIn: "8h",
    issuer: "tron-api",
    audience: "tron-client",
  });
}
export async function auth(req, res, next) {
  try {
    const raw = req.headers.authorization?.replace(/^Bearer /, "");
    ensure(raw, "Authentication required", 401);
    let token;
    try {
      token = jwt.verify(raw, cfg.secret, {
        issuer: "tron-api",
        audience: "tron-client",
      });
    } catch {
      ensure(false, "Your session has expired", 401);
    }
    const u = await User.findById(token.sub);
    ensure(
      u && u.sessionVersion === token.version,
      "Your session has expired",
      401,
    );
    ensure(u.status === "active", "Account suspended", 403);
    req.user = u;
    next();
  } catch (e) {
    next(e);
  }
}
export function admin(req, res, next) {
  try {
    ensure(req.user.role === "admin", "Super Admin access required", 403);
    next();
  } catch (e) {
    next(e);
  }
}
export function seal(data) {
  const key = Buffer.from(process.env.PAYOUT_ENCRYPTION_KEY || "", "hex");
  ensure(key.length === 32, "Payout encryption is not configured", 503);
  const iv = crypto.randomBytes(12),
    c = crypto.createCipheriv("aes-256-gcm", key, iv),
    out = Buffer.concat([c.update(JSON.stringify(data)), c.final()]);
  return [
    iv.toString("hex"),
    c.getAuthTag().toString("hex"),
    out.toString("hex"),
  ].join(":");
}
export function unseal(s) {
  const [iv, tag, data] = s.split(":").map((x) => Buffer.from(x, "hex")),
    d = crypto.createDecipheriv(
      "aes-256-gcm",
      Buffer.from(process.env.PAYOUT_ENCRYPTION_KEY, "hex"),
      iv,
    );
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString());
}
export const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");
