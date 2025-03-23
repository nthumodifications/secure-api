import { Hono } from "hono";
import kvHandler from "./kv_storage";
import { cors } from "hono/cors";

const app = new Hono()
  .use(cors({
    origin: 'https://nthumods.com',
    allowHeaders: ['Authorization'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
  }))
  .route('/kv', kvHandler)

export default app;