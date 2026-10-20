import { getSessionFromCookies, requireAdminSession } from "./auth";
import { HttpError } from "./http";
import type { SessionUser } from "./types";

export type PageAuthState =
  | { status: "anonymous" }
  | { status: "denied" }
  | { status: "admin"; session: SessionUser }
  | { status: "unavailable"; title: string; message: string };

/**
 * Page-level auth gate. Unlike the API guard, this distinguishes a real 403
 * from an unreachable auth endpoint or datastore so pages never render a
 * misleading "not authorized" or a raw 500.
 */
export async function getPageAuth(): Promise<PageAuthState> {
  let session: SessionUser | null;
  try {
    session = await getSessionFromCookies();
  } catch (error) {
    console.error("[dashboard] page session lookup failed", error);
    return {
      status: "unavailable",
      title: "Sign-in unavailable",
      message:
        "The dashboard could not reach the Supabase auth endpoint, so your session could not be verified. Try again shortly.",
    };
  }

  if (!session) return { status: "anonymous" };

  try {
    await requireAdminSession(session);
  } catch (error) {
    if (error instanceof HttpError && error.status === 403) {
      return { status: "denied" };
    }
    console.error("[dashboard] page admin check failed", error);
    return {
      status: "unavailable",
      title: "Authorization unavailable",
      message:
        "The dashboard could not verify administrator access because its datastore is unavailable.",
    };
  }

  return { status: "admin", session };
}
