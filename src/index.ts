import { Hono } from "hono";
import oidc from './oidc';
import {logger} from 'hono/logger';

export const app = new Hono()
  .use(logger())

  // CORS for cross-domain access
  .use("*", async (c, next) => {
    const origin = c.req.header("Origin");
    const allowedOrigins = [
      "http://localhost:3000",
      "https://nthumods.com",
      "https://course.nthumods.com",
    ];
    if (origin && allowedOrigins.includes(origin)) {
      c.header("Access-Control-Allow-Origin", origin);
      c.header("Access-Control-Allow-Credentials", "true");
      c.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
    }
    await next();
  })
  .get('/', async (c) => {
    return c.text("Hello, world!");
  })
  .route('/', oidc)

export default {
  port: 5002,
  fetch: app.fetch,
};