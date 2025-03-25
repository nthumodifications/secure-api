import { Hono } from "hono";
import { logger } from "hono/logger";
import { exportJWK, importPKCS8, importSPKI, jwtVerify, SignJWT } from "jose";
import { getCookie, setCookie } from "hono/cookie";
import { nthuAuth } from "./nthuoauth";
import type { NthuUser, OAuthVariables } from "./nthuoauth";
import { PrismaClient } from "@prisma/client";
import { env } from "hono/adapter";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import { addSeconds } from "date-fns";
import { cors } from "hono/cors";

// Environment validation
if (!process.env["NTHU_OAUTH_CLIENT_ID"])
  throw new Error("NTHU_OAUTH_CLIENT_ID is not set");
if (!process.env["NTHU_OAUTH_CLIENT_SECRET"])
  throw new Error("NTHU_OAUTH_CLIENT_SECRET is not set");
if (!process.env["JWT_PUBLIC_KEY"])
  throw new Error("JWT_PUBLIC_KEY is not set");
if (!process.env["JWT_PRIVATE_KEY"])
  throw new Error("JWT_PRIVATE_KEY is not set");

const prisma = new PrismaClient();
const ISSUER = "https://auth.nthumods.com";
const accessTokenExpiry: number = 30 * 60; // 30 minutes
const refreshTokenExpiry: number = 30 * 24 * 60 * 60; // 30 days
const sessionExpiry: number = 180 * 24 * 60 * 60; // 180 days
const ID_TOKEN_EXPIRY = "1h";

const VALID_SCOPES = [
  "openid", // sub
  "profile", // name, name_en, inschool
  "email", // email
  "kv",
  "calendar",
];

async function verifyPKCE(codeVerifier: string, codeChallenge: string, codeChallengeMethod: string) {
  // Input validation
  if (!codeVerifier || !codeChallenge || !codeChallengeMethod) {
      throw new Error('Missing required parameters');
  }

  // Only support S256 method
  if (codeChallengeMethod.toUpperCase() !== 'S256') {
      throw new Error('Unsupported code challenge method. Only S256 is supported');
  }

  // Verify code verifier meets basic requirements
  const verifierRegex = /^[A-Za-z0-9\-._~]{43,128}$/;
  if (!verifierRegex.test(codeVerifier)) {
      throw new Error('Invalid code verifier format');
  }

  // Convert code verifier to ArrayBuffer for crypto operations
  const encoder = new TextEncoder();
  const verifierBuffer = encoder.encode(codeVerifier);

  // Generate SHA-256 hash using Bun's Web Crypto API
  const hashBuffer = await crypto.subtle.digest('SHA-256', verifierBuffer);

  // Convert hash to base64 string
  const base64String = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

  // Apply URL-safe transformations per RFC 7636
  const generatedChallenge = base64String
      .replace(/\+/g, '-')    // Replace + with -
      .replace(/\//g, '_')    // Replace / with _
      .replace(/=/g, '');     // Remove padding

  // Simple string comparison
  // Note: For production, consider implementing timing-safe comparison
  return generatedChallenge === codeChallenge;
}

const app = new Hono()
  .use(
    "*",
    cors({
      origin: [
        "http://localhost:3000",
        "https://nthumods.com",
        "https://course.nthumods.com",
      ],
      allowHeaders: ["Authorization", "Content-Type"],
      allowMethods: ["GET", "POST"],
      credentials: true,
    }),
  )
  .get("/.well-known/openid-configuration", (c) => {
    return c.json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: VALID_SCOPES,
    });
  })
  .get("/.well-known/jwks.json", async (c) => {
    const { JWT_PUBLIC_KEY } = env<{
      JWT_PUBLIC_KEY: string;
    }>(c);
    const publicKey = await importSPKI(
      JWT_PUBLIC_KEY.replace(/\\n/g, "\n"),
      "RS256",
    );
    const jwk = await exportJWK(publicKey);
    jwk.kid = "1";
    jwk.use = "sig";
    jwk.alg = "RS256";
    jwk.kty = "RSA";
    return c.json({ keys: [jwk] });
  })
  .get(
    "/authorize",
    zValidator(
      "query",
      z.object({
        client_id: z.string(),
        redirect_uri: z.string(),
        scope: z
          .string()
          .transform((scope) => {
            const scopes = scope.split(" ");
            if (!scopes.every((scope) => VALID_SCOPES.includes(scope))) {
              throw new Error("Invalid scopes");
            }
            return scopes;
          })
          .pipe(z.string().array()),
        state: z.string().optional(),
        response_type: z.string(),
        nonce: z.string().optional(),
        ui_locales: z.string().optional(),
        code_challenge: z.string().optional(),
        code_challenge_method: z.string().optional(),
      }),
    ),
    async (c) => {
      const {
        client_id,
        redirect_uri,
        scope,
        state: clientState,
        response_type,
        nonce,
        code_challenge,
        code_challenge_method,
      } = c.req.valid("query");

      // Basic validation
      if (
        !client_id ||
        !redirect_uri ||
        !scope.includes("openid") ||
        response_type !== "code"
      ) {
        return c.json({ error: "invalid_request" }, 400);
      }

      // Check if client_id is registered
      const client = await prisma.client.findUnique({
        where: { clientId: client_id },
      });
      if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
      }

      // Check if redirect_uri is allowed for this client
      if (!client.redirectUris.includes(redirect_uri)) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "Invalid redirect_uri",
          },
          400,
        );
      }

      // only allow PCKE S256 method
      if (code_challenge_method && code_challenge_method !== "S256") {
        return c.json({ error: "invalid_request" }, 400);
      }

      // check if __session exists
      let sessionId = getCookie(c, "__session");
      
      if (sessionId) {
        // get session on prisma
        const session = await prisma.authSessions.findUnique({
          where: { sessionId },
        });

        // check if session exists
        if (session) {
          if (session.expiresAt < new Date()) {
            await prisma.authSessions.delete({
              where: { sessionId },
            });
            sessionId = undefined;
          }
          else if (session.state == 'UNAUTHENTICATED' || !session.userId) {
            // state unauthenticated, ignore. 
          }
          else {
            // resume session, we mint a authcode and redirect back to client
            const code = crypto.randomUUID();
            await prisma.authCode.create({
              data: {
                code,
                userId: session.userId,
                clientId: client_id,
                redirectUri: redirect_uri,
                expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5-minute expiry
                scopes: scope,
                nonce: nonce,
                codeChallenge: code_challenge,
                codeChallengeMethod: code_challenge_method,
              },
            });

            return c.redirect(
              `${redirect_uri}?code=${code}&state=${clientState}`,
            )
          }
        }
      }

      if (!sessionId) {
        sessionId = crypto.randomUUID();
        setCookie(c, "__session", sessionId, {
          maxAge: sessionExpiry,
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "Strict",
        });
        await prisma.authSessions.create({
          data: {
            expiresAt: addSeconds(new Date(), sessionExpiry),
            sessionId,
            state: 'UNAUTHENTICATED',
          },
        });
      }

      // create own state
      const newState = crypto.randomUUID();

      // Store Authentication Request to AuthRequest table
      const authRequest = await prisma.authRequest.create({
        data: {
          sessionId: sessionId,
          clientId: client_id,
          redirectUri: redirect_uri,
          scopes: scope,
          state: newState,
          clientState: clientState,
          nonce: nonce,
          codeChallenge: code_challenge,
          codeChallengeMethod: code_challenge_method,
        },
      });

      // Let nthuAuth handle the NTHU OAuth redirect
      const nthuAuthMiddleware = nthuAuth({
        client_id: process.env["NTHU_OAUTH_CLIENT_ID"]!,
        client_secret: process.env["NTHU_OAUTH_CLIENT_SECRET"]!,
        redirect_uri: process.env["NTHU_OAUTH_REDIRECT_URI"],
        scopes: ["userid", "name", "email", "inschool"],
        state: authRequest.state!,
      });

      // @ts-ignore
      return await nthuAuthMiddleware(c, async () => {});
    },
  )
  .get(
    "/oauth/nthu",
    zValidator(
      "query",
      z.object({
        state: z.string(),
        code: z.string(),
      }),
    ),
    async (c, next) => {
      const { state } = c.req.valid("query");
      // check prisma if such state exists
      const authRequest = await prisma.authRequest.findUnique({
        where: { state },
      });
      if (!authRequest) {
        return c.json({ error: "invalid_request" }, 400);
      }
      await next();
    },
    nthuAuth({
      client_id: process.env["NTHU_OAUTH_CLIENT_ID"],
      client_secret: process.env["NTHU_OAUTH_CLIENT_SECRET"],
      redirect_uri: process.env["NTHU_OAUTH_REDIRECT_URI"],
      scopes: ["userid", "inschool", "name", "email"],
    }),
    async (c) => {
      const user = c.var.user;
      if (!user?.userid) return c.json({ error: "User ID not available" }, 400);

      const { state } = c.req.valid("query");

      const authRequest = await prisma.authRequest.findUnique({
        where: { state },
      });
      if (!authRequest) {
        return c.json({ error: "invalid_request" }, 400);
      }

      // Authentication Approved

      

      // Store or update user in Prisma
      const upsertedUser = await prisma.user.upsert({
        where: { userId: user.userid },
        update: {
          name: user.name || "",
          nameEn: user.name_en || "",
          email: user.email || "",
          inschool: user.inschool || false,
          cid: user.cid,
          lmsid: user.lmsid,
        },
        create: {
          userId: user.userid,
          name: user.name || "",
          nameEn: user.name_en || "",
          email: user.email || "",
          inschool: user.inschool || false,
          cid: user.cid,
          lmsid: user.lmsid,
        },
      });

      await prisma.authSessions.update({
        where: { sessionId: authRequest.sessionId },
        data: {
          state: 'AUTHENTICATED',
          userId: user.userid,
          expiresAt: addSeconds(new Date(), sessionExpiry),
        },
      })
      
      setCookie(c, "__session", authRequest.sessionId, {
        maxAge: sessionExpiry,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
      });

      const {
        clientId: client_id,
        redirectUri: redirect_uri,
        scopes,
        clientState,
      } = authRequest;

      // Get client from Prisma
      const client = await prisma.client.findUnique({
        where: { clientId: client_id },
      });
      if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
      }

      // Check if redirect_uri is allowed for this client
      if (!client.redirectUris.includes(redirect_uri)) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "Invalid redirect_uri",
          },
          400,
        );
      }

      // check if the requested scopes is contained within the client scopes
      if (
        !scopes.every((s) => client.scopes.includes(s)) &&
        !scopes.includes("openid")
      ) {
        return c.json({ error: "invalid_scope" }, 400);
      }

      // Generate and store auth code
      const code = crypto.randomUUID();
      await prisma.authCode.create({
        data: {
          code,
          userId: upsertedUser.userId,
          clientId: client_id,
          redirectUri: redirect_uri,
          expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5-minute expiry
          scopes: scopes,
          nonce: authRequest.nonce,
          codeChallenge: authRequest.codeChallenge,
          codeChallengeMethod: authRequest.codeChallengeMethod,
        },
      });

      return c.redirect(`${redirect_uri}?code=${code}&state=${clientState}`);
    },
  )

  // Token Endpoint
  .post(
    "/token",
    zValidator(
      "form",
      z.union([
        z.object({
          // for grant_type: authorization_code
          grant_type: z.literal("authorization_code"),
          code: z.string().optional(),
          redirect_uri: z.string(),
          client_id: z.string(),
          code_verifier: z.string().optional(),
        }),
        z.object({
          // for grant_type: refresh_token
          grant_type: z.literal("refresh_token"),
          refresh_token: z.string(),
          scope: z.string().optional(),
        }),
      ]),
    ),
    async (c) => {
      const { JWT_PRIVATE_KEY } = env<{
        JWT_PRIVATE_KEY: string;
      }>(c);

      // Convert keys to buffers
      const privateKey = await importPKCS8(
        JWT_PRIVATE_KEY.replace(/\\n/g, "\n"),
        "RS256",
      );

      const form = c.req.valid("form");

      // Prevent caching for token endpoint
      c.res.headers.set("Cache-Control", "no-store");
      c.res.headers.set("Pragma", "no-cache");

      /* grant_type: authorization_code
       * This is the authorization code flow.
       * The client sends an authorization code to the server to get an access token.
       * The authorization code is a short-lived token that can be used only once.
       * id_token is returned in this flow.
       */
      if (form.grant_type === "authorization_code") {
        if (!form.code) return c.json({ error: "invalid_request" }, 400);
        const authCode = await prisma.authCode.findUnique({
          where: { code: form.code },
        });
        if (!authCode || authCode.expiresAt < new Date()) {
          return c.json({ error: "invalid_grant" }, 400);
        }

        // Check if client_id matches
        if (authCode.clientId !== form.client_id) {
          return c.json({ error: "invalid_client" }, 400);
        }

        // Check if redirect_uri matches
        if (authCode.redirectUri !== form.redirect_uri) {
          return c.json({ error: "invalid_request" }, 400);
        }

        // PKCE validation
        if (authCode.codeChallenge) {
          if (!form.code_verifier) {
            return c.json({ error: "invalid_request" }, 400);
          }
          if (authCode.codeChallengeMethod == "S256") {
            const verifier = form.code_verifier;
            const isValidPCKE = await verifyPKCE(
              verifier,
              authCode.codeChallenge,
              authCode.codeChallengeMethod,
            );
            if (!isValidPCKE) {
              return c.json({ error: "invalid_request" }, 400);
            }
          } else {
            return c.json({ error: "invalid_request" }, 400);
          }
        }

        const user = await prisma.user.findUnique({
          where: { userId: authCode.userId },
        });
        if (!user) return c.json({ error: "server_error" }, 500);

        // Generate refresh token and access token string, save to prisma
        const refreshToken = crypto.randomUUID();
        const accessToken = crypto.randomUUID();
        const insertRefreshToken = prisma.token.create({
          data: {
            token: refreshToken,
            type: "REFRESH",
            userId: user.userId,
            clientId: authCode.clientId,
            expiresAt: addSeconds(new Date(), refreshTokenExpiry),
            scopes: authCode.scopes,
          },
        });
        const insertAccessToken = prisma.token.create({
          data: {
            token: accessToken,
            type: "ACCESS",
            userId: user.userId,
            clientId: authCode.clientId,
            expiresAt: addSeconds(new Date(), accessTokenExpiry),
            scopes: authCode.scopes,
          },
        });
        await prisma.$transaction([insertRefreshToken, insertAccessToken]);

        /*
        OPTIONAL. Access Token hash value. 
        Its value is the base64url encoding of the left-most half of the hash 
        of the octets of the ASCII representation of the access_token value, 
        where the hash algorithm used is the hash algorithm used in the 
        alg parameter of the ID Token's JWS [JWS] header. 
        For instance, if the alg is RS256, hash the access_token value with SHA-256, 
        then take the left-most 128 bits and base64url encode them. 
        The at_hash value is a case sensitive string.
        */
        const at_hash = await crypto.subtle
          .digest("SHA-256", new TextEncoder().encode(accessToken))
          .then((hash) => {
            const hashArray = Array.from(new Uint8Array(hash));
            const leftHalf = hashArray.slice(0, hashArray.length / 2);
            return crypto.subtle.digest("SHA-256", new Uint8Array(leftHalf));
          })
          .then((leftHash) => {
            return btoa(String.fromCharCode(...new Uint8Array(leftHash)));
          });

        const idToken = await new SignJWT({
          ...(authCode.scopes.includes("openid") && { sub: user.userId }),
          ...(authCode.scopes.includes("profile") && {
            name: user.name,
            name_en: user.nameEn,
            inschool: user.inschool,
          }),
          ...(authCode.scopes.includes("email") && { email: user.email }),
          at_hash,
          nonce: authCode.nonce,
        })
          .setProtectedHeader({ alg: "RS256", kid: "1" })
          .setIssuer(ISSUER)
          .setAudience(authCode.clientId)
          .setExpirationTime(ID_TOKEN_EXPIRY)
          .sign(privateKey);

        // Delete used auth code
        await prisma.authCode.delete({ where: { code: form.code } });

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
      } else if (form.grant_type === "refresh_token") {
        /* grant_type: refresh_token
         * This is the refresh token flow.
         * The client sends a refresh token to the server to get a new access token.
         * The refresh token is a long-lived token that can be used to get a new access token.
         * id_token is not returned in this flow.
         */
        const { refresh_token } = form;
        if (!refresh_token) return c.json({ error: "invalid_request" }, 400);
        try {
          const token = await prisma.token.findUnique({
            where: { token: refresh_token, type: "REFRESH" },
          });
          if (!token) return c.json({ error: "invalid_grant" }, 400);

          // Check if it's expired
          if (token.expiresAt < new Date()) {
            await prisma.token.delete({ where: { token: refresh_token } });
            return c.json({ error: "invalid_grant" }, 400);
          }

          const user = await prisma.user.findUnique({
            where: { userId: token.userId },
          });
          if (!user) return c.json({ error: "server_error" }, 500);

          // Generate new refresh token and access token string, save to prisma
          const newRefreshToken = crypto.randomUUID();
          const newAccessToken = crypto.randomUUID();

          const deleteOldToken = prisma.token.delete({
            where: { token: refresh_token },
          });
          const insertRefreshToken = prisma.token.create({
            data: {
              token: newRefreshToken,
              type: "REFRESH",
              userId: user.userId,
              clientId: token.clientId,
              expiresAt: addSeconds(new Date(), refreshTokenExpiry),
              scopes: token.scopes,
            },
          });
          const insertAccessToken = prisma.token.create({
            data: {
              token: newAccessToken,
              type: "ACCESS",
              userId: user.userId,
              clientId: token.clientId,
              expiresAt: addSeconds(new Date(), accessTokenExpiry),
              scopes: token.scopes,
            },
          });
          await prisma.$transaction([
            deleteOldToken,
            insertRefreshToken,
            insertAccessToken,
          ]);

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
            token_type: "Bearer",
            expires_in: 15 * 60,
          });
        } catch (error) {
          return c.json({ error: "invalid_grant" }, 401);
        }
      }
      return c.json({ error: "unsupported_grant_type" }, 400);
    },
  )

  // Userinfo Endpoint
  .get("/userinfo", async (c) => {
    const accessToken =
      c.req.header("Authorization")?.split(" ")[1] ||
      getCookie(c, "access_token");
    if (!accessToken) return c.json({ error: "unauthorized" }, 401);

    try {
      const token = await prisma.token.findUnique({
        where: { token: accessToken, type: "ACCESS" },
      });
      if (!token) return c.json({ error: "invalid_token" }, 401);

      if (token.expiresAt < new Date()) {
        await prisma.token.delete({ where: { token: accessToken } });
        return c.json({ error: "invalid_token" }, 401);
      }

      const user = await prisma.user.findUnique({
        where: { userId: token.userId },
      });
      if (!user) return c.json({ error: "server_error" }, 500);

      return c.json({
        sub: user.userId,
        name: user.name,
        email: user.email,
        inschool: user.inschool,
      });
    } catch (error) {
      return c.json({ error: "invalid_token" }, 401);
    }
  })
  .post("/logout", async (c) => {
    if (c.req.header("Origin")?.includes("nthumods.com")) {
      setCookie(c, "access_token", "", {
        maxAge: 0,
        path: "/",
        domain: ".nthumods.com",
      });
    }
    return c.json({ message: "Logged out" });
  });

export default app;
