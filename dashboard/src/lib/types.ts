export type BrowserName = "chrome" | "firefox";
export type GuardAction = "reclaim_only" | "kick" | "ban";

export interface TargetConfig {
  guild_id: string;
  vanity: string;
  token?: string;
  password?: string;
  proxies?: string[];
}

export interface FingerprintConfig {
  dcfduid?: string;
  sdcfduid?: string;
  super_properties_b64?: string;
  user_agent?: string;
}

export interface SniperConfig {
  webhook_url?: string;
  totp_secret?: string;
  password?: string;
  email?: string;
  backup_codes?: string[];
  burst_count?: number;
  warm_connections?: number;
  session_path?: string;
  guard_mode?: boolean;
  guard_reclaim_max?: number;
  guard_reclaim_backoff_ms?: number;
  guard_action?: GuardAction;
  guard_protected_user_ids?: string[];
  browser?: BrowserName;
  targets: TargetConfig[];
  fingerprint?: FingerprintConfig;
}

export interface ConfigRecord {
  id: string;
  version: number;
  active: boolean;
  config: SniperConfig;
  author: string | null;
  note: string | null;
  created_at: string;
}

export interface HealthRecord {
  unit: string;
  status: string;
  last_error: string | null;
  heartbeat_at: string | null;
  last_claim_at: string | null;
  last_guard_at: string | null;
  applied_config_version: number | null;
  updated_at: string | null;
}

export type HealthState = "missing" | "ok" | "degraded" | "stale" | "drift";

export interface HealthView {
  state: HealthState;
  unit: string;
  status: string;
  heartbeatAt: string | null;
  heartbeatAgeSeconds: number | null;
  lastError: string | null;
  lastClaimAt: string | null;
  lastGuardAt: string | null;
  appliedConfigVersion: number | null;
  configDrift: boolean;
  message: string;
}

export interface AuditRecord {
  id: string;
  actor: string | null;
  action: string;
  target: string | null;
  before_hash: string | null;
  after_hash: string | null;
  result: string;
  detail: Record<string, unknown>;
  ip: string | null;
  created_at: string;
}

export interface AdminRecord {
  user_id: string;
  role: string;
  active: boolean;
}

export interface SessionUser {
  id: string;
  email: string | null;
  isDev: boolean;
}

export interface SaveConfigInput {
  config: SniperConfig;
  actor: string | null;
  note?: string | null;
  ip?: string | null;
}

export interface DashboardStore {
  getActiveConfig(): Promise<ConfigRecord | null>;
  getHealth(unit: string): Promise<HealthRecord | null>;
  listAudit(limit: number): Promise<AuditRecord[]>;
  getAdmin(userId: string): Promise<AdminRecord | null>;
  saveConfig(input: SaveConfigInput): Promise<ConfigRecord>;
  appendAudit(entry: {
    actor: string | null;
    action: string;
    target?: string | null;
    result?: "ok" | "error";
    detail?: Record<string, unknown>;
    ip?: string | null;
  }): Promise<void>;
}
