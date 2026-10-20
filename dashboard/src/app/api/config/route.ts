import { requireAdmin } from "@/lib/auth";
import { assertSameOrigin, errorResponse, HttpError, jsonResponse, readJsonBody } from "@/lib/http";
import { DASHBOARD_UNIT, getStore } from "@/lib/store";
import type { SniperConfig } from "@/lib/types";
import { mergeSecretFields, redactConfig, validateConfig } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function clientIp(request: Request): string | null {
  const candidate =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "";
  return candidate && candidate.length <= 64 ? candidate : null;
}

export async function GET(request: Request): Promise<Response> {
  try {
    await requireAdmin(request);
    const active = await getStore().getActiveConfig();
    if (!active) {
      return jsonResponse({
        unit: DASHBOARD_UNIT,
        version: null,
        config: null,
        secretStatus: null,
        updatedAt: null,
      });
    }
    const redacted = redactConfig(active.config);
    return jsonResponse({
      unit: DASHBOARD_UNIT,
      version: active.version,
      config: redacted.config,
      secretStatus: redacted.secretStatus,
      updatedAt: active.created_at,
      note: active.note,
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request): Promise<Response> {
  try {
    const session = await requireAdmin(request);
    assertSameOrigin(request);
    const body = await readJsonBody(request);
    if (!isRecord(body) || !isRecord(body.config)) {
      throw new HttpError(400, "invalid_config", "Body must contain a config object.");
    }
    if (!Array.isArray(body.config.targets)) {
      throw new HttpError(400, "invalid_config", "config.targets must be an array.");
    }
    if (body.config.targets.some((target) => !isRecord(target))) {
      throw new HttpError(400, "invalid_config", "Each config target must be an object.");
    }

    const note =
      typeof body.note === "string" ? body.note.trim().slice(0, 500) : null;
    const store = getStore();
    const current = await store.getActiveConfig();
    const merged = mergeSecretFields(
      body.config as unknown as SniperConfig,
      current?.config ?? null,
    );
    const validation = validateConfig(merged);
    if (!validation.ok) {
      return jsonResponse(
        {
          error: "validation_failed",
          message: "The config was not written.",
          details: validation.errors,
        },
        400,
      );
    }

    const saved = await store.saveConfig({
      config: validation.value,
      actor: session.id,
      note,
      ip: clientIp(request),
    });
    const redacted = redactConfig(saved.config);
    return jsonResponse(
      {
        ok: true,
        version: saved.version,
        config: redacted.config,
        secretStatus: redacted.secretStatus,
        updatedAt: saved.created_at,
        applied: false,
        message: "Config saved. The host config-sync timer applies it within 45 seconds.",
      },
      201,
    );
  } catch (error) {
    return errorResponse(error);
  }
}
