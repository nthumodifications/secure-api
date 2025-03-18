import { Hono } from "hono";
import {logger} from 'hono/logger';
import { nthuAuth, NthuUser, OAuthVariables } from "./nthuoauth";
declare module 'hono' {
  interface ContextVariableMap extends OAuthVariables {
      'user': Partial<NthuUser> | undefined
  }
}

if (!process.env.NTHU_OAUTH_CLIENT_ID) {
  throw new Error("NTHU_OAUTH_CLIENT_ID is not set");
}

if (!process.env.NTHU_OAUTH_CLIENT_SECRET) {
  throw new Error("NTHU_OAUTH_CLIENT_SECRET is not set");
}

const app = new Hono()
  .use(logger())
  .use(
    "/oauth/nthu", // -> redirect_uri by default
    nthuAuth({ 
      client_id: process.env.NTHU_OAUTH_CLIENT_ID,
      client_secret: process.env.NTHU_OAUTH_CLIENT_SECRET,
      redirect_uri: process.env.NTHU_OAUTH_REDIRECT_URI,
      scopes: ["userid", "inschool", "name", "email"]
    })
  )
  .get("/oauth/nthu", (c) => {
    const token = c.get('token')
    const grantedScopes = c.get('granted-scopes')
    const user = c.get('user')

    return c.json({
      token,
      grantedScopes,
      user,
    })
  })
  .get("/", (c) => {
    return c.text("Hello NTHUMods Auth Server!");
  })


export default {
  port: 5002,
  fetch: app.fetch,
};
