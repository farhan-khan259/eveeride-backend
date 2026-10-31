import { cfg, ensure } from "./config.js";
import mongoose from "mongoose";
import { app } from "./app.js";
import { allModels } from "./models.js";
import { runJobs } from "./jobs.js";
ensure(
  cfg.secret?.length >= 32 && !cfg.secret.startsWith("replace-with"),
  "Set JWT_SECRET to at least 32 random characters",
  500,
);
await mongoose.connect(cfg.mongo);
const hello = await mongoose.connection.db.admin().command({ hello: 1 });
ensure(
  hello.setName || hello.msg === "isdbgrid",
  "MongoDB replica set required: financial writes fail closed on standalone MongoDB",
  500,
);
await Promise.all(Object.values(allModels).map((m) => m.init()));
app.listen(cfg.port, "0.0.0.0", () =>
  console.log(`EveeRide API listening on ${cfg.port}`),
);
setInterval(
  () => runJobs().catch((e) => console.error("Background job:", e.message)),
  30000,
).unref();
