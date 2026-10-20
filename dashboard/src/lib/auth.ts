import { cookies } from "next/headers";
import { HttpError } from "./http";
import { getStore } from "./store";
import { fetchSupabaseUser } from "./supabase";
import type { SessionUser } from "./types";

export const SESSION_COOKIE = "sniper_session";

export function devAuthEnabled(): boolean {
  return process.env.DASHBOARD_AUTH_MODE === "dev" && process.env.DASHBOARD_ALLOW_DEV_AUTH === "1";
}

function devUser(): SessionUser {
  return {
    id: process.env.DASHBOARD_DEV_USER_ID ?? "00000000-0000-4000-8000-000000000001",
    email: process.env.DASHBOARD_DEV_EMAIL ?? "local@example.invalid",
    isDev: true,
  };
}

function isDevToken(token: string | undefined | null): boolean {
  const expected = process.env.DASHBOARD_DEV_TOKEN;
  return Boolean(devAuthEnabled() && expected && token && token === expected);
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.toLowerCase().startsWith("bearer ")) return null;
  const token = header.slice(7).trim();
  return token || null;
}

export async function authenticateToken(token: string | null | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  if (isDevToken(token)) return devUser();
  const user = await fetchSupabaseUser(token);
  return user ? { ...user, isDev: false } : null;
}

export async function getSessionFromRequest(request: Request): Promise<SessionUser | null> {
  const token = bearerToken(request);
  if (token) return authenticateToken(token);
  const cookieToken = request.headers
    .get("cookie")
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`))
    ?.slice(SESSION_COOKIE.length + 1);
  if (!cookieToken) return null;
  try {
    return authenticateToken(decodeURIComponent(cookieToken));
  } catch {
    return null;
  }
}

export async function getSessionFromCookies(): Promise<SessionUser | null> {
  const store = await cookies();
  return authenticateToken(store.get(SESSION_COOKIE)?.value);
}

export async function requireAdminSession(session: SessionUser): Promise<SessionUser> {
  if (session.isDev) {
    if (process.env.DASHBOARD_DEV_ADMIN === "1") return session;
    throw new HttpError(403, "not_admin", "This local account is not a dashboard administrator.");
  }
  const admin = await getStore().getAdmin(session.id);
  if (!admin?.active || admin.role !== "admin") {
    throw new HttpError(403, "not_admin", "This account is not a dashboard administrator.");
  }
  return session;
}

export async function requireAdmin(request: Request): Promise<SessionUser> {
  const session = await getSessionFromRequest(request);
  if (!session) throw new HttpError(401, "unauthenticated", "Sign in to use the dashboard.");
  return requireAdminSession(session);
}

export function sessionCookieOptions(expiresIn: number): {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  maxAge: number;
} {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: (process.env.APP_ORIGIN ?? "").startsWith("https://"),
    path: "/",
    maxAge: Math.max(60, Math.min(expiresIn, 60 * 60 * 24)),
  };
}
