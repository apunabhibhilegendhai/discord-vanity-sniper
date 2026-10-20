import { DatastoreError } from "./errors";
import { HttpError } from "./http";

const SUPABASE_URL = process.env.SUPABASE_URL?.replace(/\/$/, "") ?? "";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const REQUEST_TIMEOUT_MS = 5_000;

export function requireServerEnv(name: "SUPABASE_URL" | "SUPABASE_ANON_KEY" | "SUPABASE_SERVICE_ROLE_KEY"): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required on the dashboard host`);
  return value;
}

export function supabaseBaseUrl(): string {
  return (process.env.SUPABASE_URL ?? SUPABASE_URL).replace(/\/$/, "");
}

export function hasSupabaseServerConfig(): boolean {
  return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
}

/** Service-role access. Never import this module from a client component. */
export async function serviceRest(path: string, init: RequestInit = {}): Promise<Response> {
  const key = requireServerEnv("SUPABASE_SERVICE_ROLE_KEY");
  const url = `${supabaseBaseUrl()}/rest/v1/${path.replace(/^\//, "")}`;
  const headers = new Headers(init.headers);
  headers.set("apikey", key);
  headers.set("Authorization", `Bearer ${key}`);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[dashboard] Supabase REST request failed",
      error instanceof Error ? error.name : "unknown",
    );
    throw new DatastoreError("The dashboard datastore is unavailable.");
  }

  if (!response.ok) {
    console.error("[dashboard] Supabase REST returned", response.status);
    throw new DatastoreError("The dashboard datastore returned an error.");
  }
  return response;
}

export async function serviceJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await serviceRest(path, init);
  try {
    return (await response.json()) as T;
  } catch {
    throw new DatastoreError("The dashboard datastore returned an invalid response.");
  }
}

/** Validate a user's access token against the self-hosted /auth/v1/user endpoint. */
export async function fetchSupabaseUser(accessToken: string): Promise<{
  id: string;
  email: string | null;
} | null> {
  const anon = requireServerEnv("SUPABASE_ANON_KEY");

  let response: Response;
  try {
    response = await fetch(`${supabaseBaseUrl()}/auth/v1/user`, {
      headers: {
        apikey: anon,
        Authorization: `Bearer ${accessToken}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[dashboard] Supabase auth request failed",
      error instanceof Error ? error.name : "unknown",
    );
    throw new HttpError(
      503,
      "auth_unavailable",
      "The dashboard could not reach Supabase Auth. Try again shortly.",
    );
  }

  if (response.status === 401 || response.status === 403) return null;
  if (!response.ok) {
    console.error("[dashboard] Supabase auth returned", response.status);
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth is unavailable. Try again shortly.",
    );
  }

  let body: { id?: string; email?: string | null; sub?: string };
  try {
    body = (await response.json()) as typeof body;
  } catch {
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth returned an invalid response.",
    );
  }
  const id = body.id ?? body.sub;
  if (!id) return null;
  return { id, email: body.email ?? null };
}

/** Exchange email/password for a Supabase access token using the anon key. */
export async function passwordGrant(email: string, password: string): Promise<{
  accessToken: string;
  expiresIn: number;
  user: { id: string; email: string | null };
}> {
  const anon = requireServerEnv("SUPABASE_ANON_KEY");

  let response: Response;
  try {
    response = await fetch(`${supabaseBaseUrl()}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: {
        apikey: anon,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[dashboard] Supabase sign-in request failed",
      error instanceof Error ? error.name : "unknown",
    );
    throw new HttpError(
      503,
      "auth_unavailable",
      "The dashboard could not reach Supabase Auth. Try again shortly.",
    );
  }

  if (response.status === 400 || response.status === 401 || response.status === 403) {
    throw new HttpError(401, "invalid_credentials", "Sign-in failed.");
  }
  if (!response.ok) {
    console.error("[dashboard] Supabase sign-in returned", response.status);
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth is unavailable. Try again shortly.",
    );
  }

  let body: {
    access_token?: string;
    expires_in?: number;
    user?: { id?: string; email?: string | null };
  };
  try {
    body = (await response.json()) as typeof body;
  } catch {
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth returned an invalid response.",
    );
  }
  if (!body.access_token) {
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth returned an invalid response.",
    );
  }
  if (!body.user?.id) {
    throw new HttpError(
      503,
      "auth_unavailable",
      "Supabase Auth returned an invalid response.",
    );
  }
  return {
    accessToken: body.access_token,
    expiresIn: typeof body.expires_in === "number" ? body.expires_in : 3600,
    user: { id: body.user.id, email: body.user.email ?? null },
  };
}
