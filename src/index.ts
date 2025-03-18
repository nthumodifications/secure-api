import { Hono } from "hono";
import { nthuAuth } from "./nthuoauth/nthuAuth";

if (!process.env.NTHU_OAUTH_CLIENT_ID) {
  throw new Error("NTHU_OAUTH_CLIENT_ID is not set");
}

if (!process.env.NTHU_OAUTH_CLIENT_SECRET) {
  throw new Error("NTHU_OAUTH_CLIENT_SECRET is not set");
}

const app = new Hono()
  .use(
    "/oauth/nthu", // -> redirect_uri by default
    nthuAuth({ 
      client_id: process.env.NTHU_OAUTH_CLIENT_ID,
      client_secret: process.env.NTHU_OAUTH_CLIENT_SECRET,
      redirect_uri: process.env.NTHU_OAUTH_REDIRECT_URI,
      scopes: ["userid", "inschool", "name", "email"]
    })
  )
  .get("/", (c) => {
    return c.text("Hello NTHUMods Auth Server!");
  })


export default {
  port: 5002,
  fetch: app.fetch,
};
