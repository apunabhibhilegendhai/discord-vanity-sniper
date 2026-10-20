import { devAuthEnabled, SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth";
import { assertSameOrigin, errorResponse, HttpError, jsonResponse, readJsonBody } from "@/lib/http";
import { getStore } from "@/lib/store";
import { passwordGrant } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function cookieHeader(name: string, value: string, maxAge: number): string {
  const options = sessionCookieOptions(maxAge);
  return `${name}=${encodeURIComponent(value)}; Path=${options.path}; HttpOnly; SameSite=Lax; Max-Age=${options.maxAge}${options.secure ? "; Secure" : ""}`;
}

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const body = (await readJsonBody(request, 16 * 1024)) as {
      email?: unknown;
      password?: unknown;
      devToken?: unknown;
    };

    if (devAuthEnabled()) {
      const token = typeof body.devToken === "string" ? body.devToken : "";
      const expected = process.env.DASHBOARD_DEV_TOKEN ?? "";
      if (!token || !expected || token !== expected) {
        throw new HttpError(401, "invalid_credentials", "Invalid local development token.");
      }
      try {
        await getStore().appendAudit({
          actor: process.env.DASHBOARD_DEV_USER_ID ?? "00000000-0000-4000-8000-000000000001",
          action: "login",
          target: "dashboard",
          detail: { mode: "dev" },
        });
      } catch (error) {
        console.error("[dashboard] dev login audit failed", error);
      }
      return jsonResponse(
        { ok: true, mode: "dev" },
        200,
        { "Set-Cookie": cookieHeader(SESSION_COOKIE, token, 3600) },
      );
    }

    const email = typeof body.email === "string" ? body.email.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!email || !password) {
      throw new HttpError(400, "missing_credentials", "Email and password are required.");
    }

    let session;
    try {
      session = await passwordGrant(email, password);
    } catch (error) {
      console.error("[dashboard] sign-in failed", error);
      if (error instanceof HttpError) throw error;
      throw new HttpError(401, "invalid_credentials", "Sign-in failed.");
    }

    try {
      await getStore().appendAudit({
        actor: session.user.id,
        action: "login",
        target: "dashboard",
        detail: { mode: "supabase" },
      });
    } catch (error) {
      console.error("[dashboard] login audit failed", error);
    }

    return jsonResponse(
      { ok: true, mode: "supabase" },
      200,
      { "Set-Cookie": cookieHeader(SESSION_COOKIE, session.accessToken, session.expiresIn) },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
