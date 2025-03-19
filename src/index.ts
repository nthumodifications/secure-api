import { Hono } from "hono";
import oidc from './oidc';

const app = new Hono()
  .route('/', oidc)
  .get('/', async (c) => {
    return c.text("Hello, world!");
  })

export default {
  port: 5002,
  fetch: app.fetch,
};