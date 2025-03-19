import { Context, Next } from "hono";
import { jwtVerify } from "jose";
import { PrismaClient } from "@prisma/client";
import { getCookie } from "hono/cookie";

const prisma = new PrismaClient();
const SECRET = new TextEncoder().encode(process.env.JWT_SECRET || ""); // Ensure JWT_SECRET is set in .env

// Middleware to check authentication and scopes
export const requireAuth = (requiredScopes: string[] = []) => async (c: Context, next: Next) => {
  // Extract access_token from cookie or Authorization header
  const accessToken = c.req.header("Authorization")?.split(" ")[1] || getCookie(c, "access_token");
  
  if (!accessToken) {
    return c.json({ error: "unauthorized", error_description: "Access token required" }, 401);
  }
  
  try {
    const { payload } = await jwtVerify(accessToken, SECRET, {
      issuer: "https://auth.nthumods.com",
      requiredClaims: ["sub", "scope"],
    });

    const user = await prisma.user.findUnique({ where: { userid: payload.sub as string } });
    if (!user) {
      return c.json({ error: "not_found", error_description: "User not found" }, 404);
    }

    c.set("userId", payload.sub);

    if (requiredScopes.length > 0) {
      const tokenScopes = (payload.scope as string)?.split(" ") || [];
      
      // Check if all required scopes are satisfied
      const hasRequiredScopes = requiredScopes.every((requiredScope) => {
        const [reqResource, reqPermission] = requiredScope.split(":");
        
        // If no permission is specified (e.g., "user"), just check resource presence
        if (!reqPermission) {
          return tokenScopes.some((scope) => scope.split(":")[0] === reqResource);
        }

        // Otherwise, check exact match (e.g., "user:read")
        return tokenScopes.includes(requiredScope);
      });

      if (!hasRequiredScopes) {
        return c.json(
          { 
            error: "insufficient_scope", 
            error_description: `Required scopes: ${requiredScopes.join(", ")}` 
          }, 
          403
        );
      }
    }

    await next();
  } catch (error) {
    return c.json({ error: "invalid_token", error_description: "Invalid or expired token" }, 401);
  }
};