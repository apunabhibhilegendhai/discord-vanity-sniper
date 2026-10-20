import { DatastoreError } from "./errors";

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: HeadersInit = {},
): Response {
  const merged = new Headers(headers);
  merged.set("Content-Type", "application/json; charset=utf-8");
  merged.set("Cache-Control", "no-store, max-age=0");
  merged.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(body), { status, headers: merged });
}

export function errorResponse(error: unknown): Response {
  if (error instanceof HttpError) {
    return jsonResponse(
      { error: error.code, message: error.message, details: error.details },
      error.status,
    );
  }
  if (error instanceof DatastoreError) {
    console.error("[dashboard] datastore unavailable", error.message);
    return jsonResponse(
      { error: "datastore_unavailable", message: error.message },
      503,
    );
  }
  console.error("[dashboard] unhandled error", error);
  return jsonResponse(
    { error: "internal_error", message: "The dashboard could not complete that request." },
    500,
  );
}

export async function readJsonBody(request: Request, maxBytes = 256 * 1024): Promise<unknown> {
  const length = request.headers.get("content-length");
  if (length && Number(length) > maxBytes) {
    throw new HttpError(413, "payload_too_large", "Request body is too large.");
  }
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    throw new HttpError(413, "payload_too_large", "Request body is too large.");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON.");
  }
}

/**
 * Cookie-backed mutations must come from the dashboard origin. Bearer-token
 * requests are allowed without Origin so CLI/API clients and tests can call the
 * route directly; browsers never attach the session cookie to another origin.
 */
export function assertSameOrigin(request: Request): void {
  if (request.headers.get("authorization")) return;
  const origin = request.headers.get("origin");
  if (!origin) {
    throw new HttpError(403, "origin_required", "Origin header is required for cookie-backed writes.");
  }
  const configured = process.env.APP_ORIGIN?.replace(/\/$/, "");
  const expected = configured || new URL(request.url).origin;
  if (origin.replace(/\/$/, "") !== expected) {
    throw new HttpError(403, "bad_origin", "Request origin is not allowed.");
  }
}
