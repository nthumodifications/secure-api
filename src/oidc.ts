import { Hono } from "hono";
import { logger } from "hono/logger";
import { jwtVerify, SignJWT } from "jose";
import { getCookie, setCookie } from "hono/cookie";
import { nthuAuth, NthuUser, OAuthVariables } from "./nthuoauth";
import { PrismaClient } from '@prisma/client'
import { env } from "hono/adapter";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";

declare module "hono" {
  interface ContextVariableMap extends OAuthVariables {
    user: Partial<NthuUser> | undefined;
  }
}

// Environment validation
if (!process.env.NTHU_OAUTH_CLIENT_ID) throw new Error("NTHU_OAUTH_CLIENT_ID is not set");
if (!process.env.NTHU_OAUTH_CLIENT_SECRET) throw new Error("NTHU_OAUTH_CLIENT_SECRET is not set");
if (!process.env.JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET is not set");
if (!process.env.JWT_ACCESS_SECRET) throw new Error("JWT_ACCESS_SECRET is not set");

const prisma = new PrismaClient();
const ISSUER = "https://auth.nthumods.com";
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";
const ID_TOKEN_EXPIRY = "1h";

const VALID_SCOPES = ["openid", "user", "user:read", "user:write", "courses:read", "courses:write"];
const app = new Hono()
  .use(logger())

  // CORS for cross-domain access
  .use("*", async (c, next) => {
    const origin = c.req.header("Origin");
    const allowedOrigins = [
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

  // OIDC Discovery Endpoint
  .get("/.well-known/openid-configuration", (c) => {
    return c.json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`, // Placeholder for future JWKS
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["HS256"],
    });
  })

  // Authorization Endpoint
  .get("/authorize", zValidator(
    "query",
    z.object({
      client_id: z.string(),
      redirect_uri: z.string(),
      state: z.string(),
      scope: z.string(),
      response_type: z.string(),
    }),
  ), async (c) => {
    const { client_id, redirect_uri, state, scope, response_type } = c.req.valid("query");
    if (!client_id || !redirect_uri || !scope.includes("openid") || response_type !== "code") {
      return c.json({ error: "invalid_request" }, 400);
    }

    // Redirect to NTHU OAuth with embedded OIDC params in state
    const nthuRedirect = `${process.env.NTHU_OAUTH_AUTH_URL}?client_id=${process.env.NTHU_OAUTH_CLIENT_ID}&redirect_uri=${ISSUER}/oauth/nthu&state=${encodeURIComponent(`${state}|${client_id}|${redirect_uri}`)}&scope=user_id,name,email`;
    return c.redirect(nthuRedirect);
  })
  // NTHU OAuth Callback
  .use("/oauth/nthu", nthuAuth({
    client_id: process.env.NTHU_OAUTH_CLIENT_ID,
    client_secret: process.env.NTHU_OAUTH_CLIENT_SECRET,
    redirect_uri: `${ISSUER}/oauth/nthu`,
    scopes: ["userid", "inschool", "name", "email"],
  }))
  .get("/oauth/nthu",
    zValidator(
      'query',
      z.object({
        state: z.string(),
      })
    ),
    async (c) => {
      const user = c.get("user");
      if (!user?.userid) return c.json({ error: "User ID not available" }, 400);

      const { state: stateStr } = c.req.valid("query");
      const [state, client_id, redirect_uri] = stateStr?.split("|") || [];
      if (!state || !client_id || !redirect_uri) return c.json({ error: "Invalid state" }, 400);

      // Store or update user in Prisma
      await prisma.user.upsert({
        where: { userid: user.userid },
        update: {
          name: user.name || "",
          nameEn: user.name_en || "",
          email: user.email || "",
          inschool: user.inschool || false,
          cid: user.cid,
          lmsid: user.lmsid,
        },
        create: {
          userid: user.userid,
          name: user.name || "",
          nameEn: user.name_en || "",
          email: user.email || "",
          inschool: user.inschool || false,
          cid: user.cid,
          lmsid: user.lmsid,
        },
      });

      // Generate and store auth code
      const code = crypto.randomUUID();
      await prisma.authCode.create({
        data: {
          code,
          userId: user.userid,
          clientId: client_id,
          redirectUri: redirect_uri,
          expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5-minute expiry
        },
      });

      return c.redirect(`${redirect_uri}?code=${code}&state=${state}`);
    })

  // Token Endpoint
  .post("/token",
    zValidator(
      'json',
      z.object({
        grant_type: z.string(),
        code: z.string().optional(),
        refresh_token: z.string().optional(),
      })
    ),
    async (c) => {
      const { JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, JWT_IDTOKEN_SECRET } = env<{
        JWT_ACCESS_SECRET: string;
        JWT_REFRESH_SECRET: string;
        JWT_IDTOKEN_SECRET: string;
      }>(c);

      const ACCESS_SECRET = new TextEncoder().encode(JWT_ACCESS_SECRET);
      const REFRESH_SECRET = new TextEncoder().encode(JWT_REFRESH_SECRET);
      const IDTOKEN_SECRET = new TextEncoder().encode(JWT_IDTOKEN_SECRET);

      const { grant_type, code, refresh_token } = c.req.valid("json");

      if (grant_type === "authorization_code") {
        if (!code) return c.json({ error: "invalid_request" }, 400);
        const authCode = await prisma.authCode.findUnique({ where: { code } });
        if (!authCode || authCode.expiresAt < new Date()) {
          return c.json({ error: "invalid_grant" }, 400);
        }

        const user = await prisma.user.findUnique({ where: { userid: authCode.userId } });
        if (!user) return c.json({ error: "server_error" }, 500);

        const accessToken = await new SignJWT({ sub: user.userid, scope: "openid profile email" })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuer(ISSUER)
          .setAudience(authCode.clientId)
          .setExpirationTime(ACCESS_TOKEN_EXPIRY)
          .sign(ACCESS_SECRET);

        const refreshToken = await new SignJWT({ sub: user.userid })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuer(ISSUER)
          .setAudience(authCode.clientId)
          .setExpirationTime(REFRESH_TOKEN_EXPIRY)
          .sign(REFRESH_SECRET);

        const idToken = await new SignJWT({
          sub: user.userid,
          name: user.name,
          name_en: user.nameEn,
          email: user.email,
          inschool: user.inschool,
        })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuer(ISSUER)
          .setAudience(authCode.clientId)
          .setExpirationTime(ID_TOKEN_EXPIRY)
          .sign(IDTOKEN_SECRET);

        // Delete used auth code
        await prisma.authCode.delete({ where: { code } });

        if (c.req.header("Origin")?.includes("nthumods.com")) {
          setCookie(c, "access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            maxAge: 15 * 60,
            path: "/",
            domain: ".nthumods.com",
          });
        }

        return c.json({
          access_token: accessToken,
          refresh_token: refreshToken,
          id_token: idToken,
          token_type: "Bearer",
          expires_in: 15 * 60,
        });
      } else if (grant_type === "refresh_token") {
        if (!refresh_token) return c.json({ error: "invalid_request" }, 400);
        try {
          const { payload } = await jwtVerify(refresh_token, REFRESH_SECRET);
          const userId = payload.sub as string;
          const user = await prisma.user.findUnique({ where: { userid: userId } });
          if (!user) return c.json({ error: "invalid_grant" }, 400);

          const newAccessToken = await new SignJWT({ sub: userId, scope: "openid profile email" })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(ISSUER)
            .setAudience(payload.aud as string)
            .setExpirationTime(ACCESS_TOKEN_EXPIRY)
            .sign(ACCESS_SECRET);

          const newRefreshToken = await new SignJWT({ sub: userId })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(ISSUER)
            .setAudience(payload.aud as string)
            .setExpirationTime(REFRESH_TOKEN_EXPIRY)
            .sign(REFRESH_SECRET);

          const newIdToken = await new SignJWT({
            sub: user.userid,
            name: user.name,
            email: user.email,
            inschool: user.inschool,
          })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(ISSUER)
            .setAudience(payload.aud as string)
            .setExpirationTime(ID_TOKEN_EXPIRY)
            .sign(IDTOKEN_SECRET);

          if (c.req.header("Origin")?.includes("nthumods.com")) {
            setCookie(c, "access_token", newAccessToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production",
              sameSite: "Strict",
              maxAge: 15 * 60,
              path: "/",
              domain: ".nthumods.com",
            });
          }

          return c.json({
            access_token: newAccessToken,
            refresh_token: newRefreshToken,
            id_token: newIdToken,
            token_type: "Bearer",
            expires_in: 15 * 60,
          });
        } catch (error) {
          return c.json({ error: "invalid_grant" }, 401);
        }
      }
      return c.json({ error: "unsupported_grant_type" }, 400);
    })

  // Userinfo Endpoint
  .get("/userinfo", async (c) => {
    const { JWT_ACCESS_SECRET } = env<{
      JWT_ACCESS_SECRET: string;
    }>(c);

    const ACCESS_SECRET = new TextEncoder().encode(JWT_ACCESS_SECRET);

    const accessToken = c.req.header("Authorization")?.split(" ")[1] || getCookie(c, "access_token");
    if (!accessToken) return c.json({ error: "unauthorized" }, 401);

    try {
      const { payload } = await jwtVerify(accessToken, ACCESS_SECRET);
      const user = await prisma.user.findUnique({ where: { userid: payload.sub as string } });
      if (!user) return c.json({ error: "not_found" }, 404);

      return c.json({
        sub: user.userid,
        name: user.name,
        email: user.email,
        inschool: user.inschool,
      });
    } catch (error) {
      return c.json({ error: "invalid_token" }, 401);
    }
  })

  // Logout Endpoint
  .post("/logout", async (c) => {
    if (c.req.header("Origin")?.includes("nthumods.com")) {
      setCookie(c, "access_token", "", {
        maxAge: 0,
        path: "/",
        domain: ".nthumods.com",
      });
    }
    return c.json({ message: "Logged out" });
  })

export default app;