import { Hono } from "hono";
import { cors } from "hono/cors";

import kvHandler from "./kv_storage";
import calendarHandler from "./calendar";

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
  .route("/calendar", calendarHandler);

export default app;
