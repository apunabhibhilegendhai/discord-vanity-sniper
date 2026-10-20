import type {
  FingerprintConfig,
  SniperConfig,
  TargetConfig,
} from "./types";

export interface SecretStatus {
  webhook_url: boolean;
  totp_secret: boolean;
  password: boolean;
  backup_codes: number;
  targets: Record<string, { token: boolean; password: boolean }>;
}

export type ValidationResult =
  | { ok: true; value: SniperConfig }
  | { ok: false; errors: string[] };

const TOP_LEVEL_KEYS = new Set([
  "webhook_url",
  "totp_secret",
  "password",
  "email",
  "backup_codes",
  "burst_count",
  "warm_connections",
  "session_path",
  "guard_mode",
  "guard_reclaim_max",
  "guard_reclaim_backoff_ms",
  "guard_action",
  "guard_protected_user_ids",
  "browser",
  "targets",
  "fingerprint",
]);

const TARGET_KEYS = new Set([
  "guild_id",
  "vanity",
  "token",
  "password",
  "proxies",
]);

const FINGERPRINT_KEYS = new Set([
  "dcfduid",
  "sdcfduid",
  "super_properties_b64",
  "user_agent",
]);

const GUILD_ID = /^[0-9]{17,20}$/;
const VANITY = /^[A-Za-z0-9-]{2,32}$/;
const BASE32 = /^[A-Z2-7]+=*$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknown(
  record: Record<string, unknown>,
  allowed: Set<string>,
  path: string,
  errors: string[],
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) errors.push(`${path}.${key} is not a recognized field`);
  }
}

function optionalString(
  record: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
  max: number,
): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    errors.push(`${path}.${key} must be a string`);
    return undefined;
  }
  if (value.length > max) {
    errors.push(`${path}.${key} is longer than ${max} characters`);
    return undefined;
  }
  return value;
}

function optionalInteger(
  record: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
  min: number,
  max: number,
): number | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    errors.push(`${path}.${key} must be an integer`);
    return undefined;
  }
  if (value < min || value > max) {
    errors.push(`${path}.${key} must be between ${min} and ${max}`);
    return undefined;
  }
  return value;
}

function optionalBoolean(
  record: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
): boolean | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") {
    errors.push(`${path}.${key} must be a boolean`);
    return undefined;
  }
  return value;
}

function optionalStringArray(
  record: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
  maxItems: number,
  maxLength: number,
): string[] | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    errors.push(`${path}.${key} must be an array of strings`);
    return undefined;
  }
  if (value.length > maxItems) {
    errors.push(`${path}.${key} has more than ${maxItems} entries`);
    return undefined;
  }
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item !== "string" || item.length > maxLength) {
      errors.push(`${path}.${key}[${i}] must be a string of at most ${maxLength} characters`);
      continue;
    }
    out.push(item);
  }
  return out;
}

function validateTarget(
  raw: unknown,
  index: number,
  errors: string[],
): TargetConfig | null {
  const path = `config.targets[${index}]`;
  if (!isRecord(raw)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  rejectUnknown(raw, TARGET_KEYS, path, errors);

  const guildId = optionalString(raw, "guild_id", path, errors, 20);
  const vanity = optionalString(raw, "vanity", path, errors, 32);
  if (!guildId) {
    errors.push(`${path}.guild_id is required`);
  } else if (!GUILD_ID.test(guildId)) {
    errors.push(`${path}.guild_id must be a 17–20 digit Discord id`);
  }
  if (!vanity) {
    errors.push(`${path}.vanity is required`);
  } else if (!VANITY.test(vanity)) {
    errors.push(`${path}.vanity must be 2–32 letters, digits, or hyphens`);
  }

  const token = optionalString(raw, "token", path, errors, 4096);
  const password = optionalString(raw, "password", path, errors, 512);
  const proxies = optionalStringArray(raw, "proxies", path, errors, 20, 2048);
  if (proxies) {
    for (let i = 0; i < proxies.length; i++) {
      const proxy = proxies[i];
      if (proxy === "") continue;
      try {
        const parsed = new URL(proxy);
        if (!["http:", "https:", "socks5:"].includes(parsed.protocol)) {
          errors.push(`${path}.proxies[${i}] must use http, https, or socks5`);
        }
      } catch {
        errors.push(`${path}.proxies[${i}] is not a valid URL`);
      }
    }
  }

  if (!guildId || !vanity) return null;
  const target: TargetConfig = { guild_id: guildId, vanity };
  if (token !== undefined) target.token = token;
  if (password !== undefined) target.password = password;
  if (proxies !== undefined) target.proxies = proxies;
  return target;
}

/** Validate the merged config, rejecting unknown fields instead of silently dropping them. */
export function validateConfig(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["config must be a JSON object"] };
  }
  rejectUnknown(input, TOP_LEVEL_KEYS, "config", errors);

  const webhookUrl = optionalString(input, "webhook_url", "config", errors, 2048);
  if (webhookUrl) {
    try {
      const parsed = new URL(webhookUrl);
      const host = parsed.hostname.toLowerCase();
      if (parsed.protocol !== "https:" || !(
        host === "discord.com" ||
        host === "discordapp.com" ||
        host.endsWith(".discord.com")
      )) {
        errors.push("config.webhook_url must be an https Discord webhook URL");
      }
    } catch {
      errors.push("config.webhook_url is not a valid URL");
    }
  }

  const totpSecret = optionalString(input, "totp_secret", "config", errors, 64);
  if (totpSecret && !BASE32.test(totpSecret)) {
    errors.push("config.totp_secret must be a base32 secret");
  }

  const password = optionalString(input, "password", "config", errors, 512);
  const email = optionalString(input, "email", "config", errors, 320);
  if (email && !EMAIL.test(email)) errors.push("config.email is not a valid email address");

  const backupCodes = optionalStringArray(input, "backup_codes", "config", errors, 20, 64);
  const burstCount = optionalInteger(input, "burst_count", "config", errors, 1, 50);
  const warmConnections = optionalInteger(input, "warm_connections", "config", errors, 1, 50);
  const sessionPath = optionalString(input, "session_path", "config", errors, 512);
  if (sessionPath && (sessionPath.includes("..") || sessionPath.includes("\0"))) {
    errors.push("config.session_path must not contain '..' or NUL");
  }

  const guardMode = optionalBoolean(input, "guard_mode", "config", errors);
  const guardReclaimMax = optionalInteger(input, "guard_reclaim_max", "config", errors, 1, 20);
  const guardReclaimBackoffMS = optionalInteger(
    input,
    "guard_reclaim_backoff_ms",
    "config",
    errors,
    0,
    60_000,
  );
  const guardAction = optionalString(input, "guard_action", "config", errors, 16);
  if (guardAction && !["reclaim_only", "kick", "ban"].includes(guardAction)) {
    errors.push("config.guard_action must be reclaim_only, kick, or ban");
  }

  const protectedIds = optionalStringArray(
    input,
    "guard_protected_user_ids",
    "config",
    errors,
    100,
    20,
  );
  if (protectedIds) {
    for (let i = 0; i < protectedIds.length; i++) {
      if (!GUILD_ID.test(protectedIds[i])) {
        errors.push(`config.guard_protected_user_ids[${i}] must be a Discord user id`);
      }
    }
  }

  const browser = optionalString(input, "browser", "config", errors, 16);
  if (browser && !["chrome", "firefox"].includes(browser)) {
    errors.push("config.browser must be chrome or firefox");
  }

  let fingerprint: FingerprintConfig | undefined;
  if (input.fingerprint !== undefined) {
    if (!isRecord(input.fingerprint)) {
      errors.push("config.fingerprint must be an object");
    } else {
      rejectUnknown(input.fingerprint, FINGERPRINT_KEYS, "config.fingerprint", errors);
      fingerprint = {};
      for (const key of FINGERPRINT_KEYS) {
        const value = optionalString(input.fingerprint, key, "config.fingerprint", errors, 4096);
        if (value !== undefined) fingerprint[key as keyof FingerprintConfig] = value;
      }
    }
  }

  const targetsRaw = input.targets;
  if (!Array.isArray(targetsRaw) || targetsRaw.length === 0) {
    errors.push("config.targets must contain at least one target");
  } else if (targetsRaw.length > 100) {
    errors.push("config.targets cannot contain more than 100 targets");
  }

  const targets: TargetConfig[] = [];
  if (Array.isArray(targetsRaw)) {
    for (let i = 0; i < targetsRaw.length && i < 100; i++) {
      const target = validateTarget(targetsRaw[i], i, errors);
      if (target) targets.push(target);
    }
  }

  const guildIds = new Set<string>();
  for (const target of targets) {
    if (guildIds.has(target.guild_id)) {
      errors.push(`config target ${target.guild_id} is duplicated`);
    }
    guildIds.add(target.guild_id);
  }

  const targetsNeedingLogin = targets.filter((target) => !target.token);
  if (targetsNeedingLogin.length > 0) {
    if (!email) {
      errors.push("config.email is required when any target has no token");
    }
    for (const target of targetsNeedingLogin) {
      if (!target.password && !password) {
        errors.push(`target ${target.guild_id} has no token and no password for auto-login`);
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  const value: SniperConfig = { targets };
  if (webhookUrl !== undefined) value.webhook_url = webhookUrl;
  if (totpSecret !== undefined) value.totp_secret = totpSecret;
  if (password !== undefined) value.password = password;
  if (email !== undefined) value.email = email;
  if (backupCodes !== undefined) value.backup_codes = backupCodes;
  if (burstCount !== undefined) value.burst_count = burstCount;
  if (warmConnections !== undefined) value.warm_connections = warmConnections;
  if (sessionPath !== undefined) value.session_path = sessionPath;
  if (guardMode !== undefined) value.guard_mode = guardMode;
  if (guardReclaimMax !== undefined) value.guard_reclaim_max = guardReclaimMax;
  if (guardReclaimBackoffMS !== undefined) value.guard_reclaim_backoff_ms = guardReclaimBackoffMS;
  if (guardAction !== undefined) value.guard_action = guardAction as SniperConfig["guard_action"];
  if (protectedIds !== undefined) value.guard_protected_user_ids = protectedIds;
  if (browser !== undefined) value.browser = browser as SniperConfig["browser"];
  if (fingerprint !== undefined) value.fingerprint = fingerprint;
  return { ok: true, value };
}

/**
 * A config GET is redacted, so the editor intentionally leaves secret fields
 * absent. On write, absent means "keep the current value"; an explicitly empty
 * string means "clear it".
 */
export function mergeSecretFields(
  incoming: SniperConfig,
  current: SniperConfig | null,
): SniperConfig {
  const next: SniperConfig = {
    ...incoming,
    targets: incoming.targets.map((target) => ({ ...target })),
  };
  if (!current) return next;

  const currentTargets = new Map(current.targets.map((target) => [target.guild_id, target]));

  if (next.webhook_url === undefined) next.webhook_url = current.webhook_url;
  if (next.totp_secret === undefined) next.totp_secret = current.totp_secret;
  if (next.password === undefined) next.password = current.password;
  if (next.backup_codes === undefined) next.backup_codes = current.backup_codes;
  if (next.fingerprint === undefined) next.fingerprint = current.fingerprint;

  for (const target of next.targets) {
    const previous = currentTargets.get(target.guild_id);
    if (!previous) continue;
    if (target.token === undefined) target.token = previous.token;
    if (target.password === undefined) target.password = previous.password;
  }
  return next;
}

export function redactConfig(config: SniperConfig): {
  config: SniperConfig;
  secretStatus: SecretStatus;
} {
  const redacted: SniperConfig = {
    ...config,
    targets: config.targets.map((target) => {
      const copy = { ...target };
      delete copy.token;
      delete copy.password;
      return copy;
    }),
  };
  delete redacted.webhook_url;
  delete redacted.totp_secret;
  delete redacted.password;
  delete redacted.backup_codes;

  const targets: SecretStatus["targets"] = {};
  for (const target of config.targets) {
    targets[target.guild_id] = {
      token: Boolean(target.token),
      password: Boolean(target.password),
    };
  }

  return {
    config: redacted,
    secretStatus: {
      webhook_url: Boolean(config.webhook_url),
      totp_secret: Boolean(config.totp_secret),
      password: Boolean(config.password),
      backup_codes: config.backup_codes?.length ?? 0,
      targets,
    },
  };
}
