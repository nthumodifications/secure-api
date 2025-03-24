import { Hono } from "hono";
import { cors } from "hono/cors";

import kvHandler from "./kv_storage";
import replicationHandler from "./replication";

const app = new Hono()
  .use(
    cors({
      origin: "https://nthumods.com",
      allowHeaders: ["Authorization"],
      allowMethods: ["GET", "POST", "OPTIONS"],
      credentials: true,
    }),
  )
  .route("/kv", kvHandler)
  .route("/replication", replicationHandler);

export default app;
