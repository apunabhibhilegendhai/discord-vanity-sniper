import type { HealthRecord, HealthView } from "./types";

export const STALE_HEARTBEAT_SECONDS = 90;

function recordLabel(
  value: unknown,
  fallback: string,
  field: string,
  malformed: string[],
): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  malformed.push(field);
  return fallback;
}

function recordText(value: unknown, field: string, malformed: string[]): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    malformed.push(field);
    return null;
  }
  return value === "" ? null : value;
}

function recordTimestamp(value: unknown, field: string, malformed: string[]): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    malformed.push(field);
    return null;
  }
  return value;
}

function recordVersion(value: unknown, malformed: string[]): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return value;
  malformed.push("applied_config_version");
  return null;
}

export function buildHealthView(
  record: HealthRecord | null,
  now = new Date(),
  storedVersion: number | null = null,
): HealthView {
  if (!record) {
    return {
      state: "missing",
      unit: "unknown",
      status: "unknown",
      heartbeatAt: null,
      heartbeatAgeSeconds: null,
      lastError: null,
      lastClaimAt: null,
      lastGuardAt: null,
      appliedConfigVersion: null,
      configDrift: false,
      message:
        "No health sidecar data yet. The dashboard can only show stored rows; it does not inspect the sniper process directly.",
    };
  }

  const malformed: string[] = [];
  const unit = recordLabel(record.unit, "unknown", "unit", malformed);
  const status = recordLabel(record.status, "unknown", "status", malformed);
  const lastError = recordText(record.last_error, "last_error", malformed);
  const lastClaimAt = recordTimestamp(record.last_claim_at, "last_claim_at", malformed);
  const lastGuardAt = recordTimestamp(record.last_guard_at, "last_guard_at", malformed);
  const appliedVersion = recordVersion(record.applied_config_version, malformed);
  const stored =
    typeof storedVersion === "number" && Number.isSafeInteger(storedVersion) && storedVersion > 0
      ? storedVersion
      : null;

  const rawHeartbeat = record.heartbeat_at;
  const heartbeatAt = recordTimestamp(rawHeartbeat, "heartbeat_at", malformed);
  const hasHeartbeat = heartbeatAt !== null;
  const heartbeatMs = hasHeartbeat ? Date.parse(heartbeatAt) : Number.NaN;
  const ageSeconds = hasHeartbeat
    ? Math.max(0, Math.floor((now.getTime() - heartbeatMs) / 1000))
    : null;
  const configDrift =
    stored !== null && appliedVersion !== null && stored !== appliedVersion;

  let state: HealthView["state"];
  let message: string;
  if (!hasHeartbeat) {
    state = "degraded";
    message =
      rawHeartbeat === null || rawHeartbeat === undefined
        ? "The sidecar row exists, but no heartbeat timestamp has been recorded."
        : "The sidecar heartbeat timestamp is invalid.";
  } else if (ageSeconds !== null && ageSeconds > STALE_HEARTBEAT_SECONDS) {
    state = "stale";
    message = `Heartbeat is ${ageSeconds}s old (stale after ${STALE_HEARTBEAT_SECONDS}s).`;
  } else if (status !== "active") {
    state = "degraded";
    message = `Service status is "${status}", not active.`;
  } else if (lastError) {
    state = "degraded";
    message = "Service is active, but the sidecar recorded an error.";
  } else if (configDrift) {
    state = "drift";
    message = `Stored config v${stored} has not been applied; the sidecar reports v${appliedVersion}. Check sniper-config-sync.`;
  } else {
    state = "ok";
    message = "Service is active and the heartbeat is fresh.";
  }

  if (malformed.length > 0) {
    if (state === "ok") state = "degraded";
    message += ` Malformed fields: ${[...new Set(malformed)].join(", ")}.`;
  }

  return {
    state,
    unit,
    status,
    heartbeatAt: hasHeartbeat ? heartbeatAt : null,
    heartbeatAgeSeconds: ageSeconds,
    lastError,
    lastClaimAt,
    lastGuardAt,
    appliedConfigVersion: appliedVersion,
    configDrift,
    message,
  };
}
