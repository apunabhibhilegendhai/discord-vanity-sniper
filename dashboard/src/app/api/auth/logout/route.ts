import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth";
import { assertSameOrigin, errorResponse, jsonResponse } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const options = sessionCookieOptions(0);
    return jsonResponse(
      { ok: true },
      200,
      {
        "Set-Cookie": `${SESSION_COOKIE}=; Path=${options.path}; HttpOnly; SameSite=Lax; Max-Age=0${options.secure ? "; Secure" : ""}`,
      },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
