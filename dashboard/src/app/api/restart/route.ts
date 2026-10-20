import { requireAdmin } from "@/lib/auth";
import { restartSniper } from "@/lib/host";
import { assertSameOrigin, errorResponse, HttpError, jsonResponse } from "@/lib/http";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

let lastRestartAt = 0;
const RESTART_COOLDOWN_MS = 10_000;

function clientIp(request: Request): string | null {
  const candidate =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "";
  return candidate && candidate.length <= 64 ? candidate : null;
}

export async function POST(request: Request): Promise<Response> {
  try {
    const session = await requireAdmin(request);
    assertSameOrigin(request);
    const now = Date.now();
    if (now - lastRestartAt < RESTART_COOLDOWN_MS) {
      throw new HttpError(429, "restart_cooldown", "A restart was requested moments ago.");
    }

    try {
      const result = await restartSniper();
      lastRestartAt = Date.now();
      try {
        await getStore().appendAudit({
          actor: session.id,
          action: "restart",
          target: "discord-sniper.service",
          detail: { output: result.output.slice(0, 1000) },
          ip: clientIp(request),
        });
      } catch (auditError) {
        console.error("[dashboard] restart audit failed", auditError);
      }
      return jsonResponse({ ok: true, output: result.output });
    } catch (error) {
      try {
        await getStore().appendAudit({
          actor: session.id,
          action: "restart",
          target: "discord-sniper.service",
          result: "error",
          detail: { error: error instanceof Error ? error.message.slice(0, 1000) : "unknown" },
          ip: clientIp(request),
        });
      } catch (auditError) {
        console.error("[dashboard] restart audit failed", auditError);
      }
      throw error;
    }
  } catch (error) {
    return errorResponse(error);
  }
}
