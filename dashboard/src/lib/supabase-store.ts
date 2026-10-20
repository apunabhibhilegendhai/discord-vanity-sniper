import { serviceJson, serviceRest } from "./supabase";
import type {
  AdminRecord,
  AuditRecord,
  ConfigRecord,
  DashboardStore,
  HealthRecord,
  SaveConfigInput,
} from "./types";

function one<T>(value: T | T[] | null): T | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value;
}

export class SupabaseStore implements DashboardStore {
  async getActiveConfig(): Promise<ConfigRecord | null> {
    const rows = await serviceJson<ConfigRecord[]>(
      "sniper_configs?select=id,version,active,config,author,note,created_at&active=eq.true&limit=1",
    );
    return rows[0] ?? null;
  }

  async getHealth(unit: string): Promise<HealthRecord | null> {
    const rows = await serviceJson<HealthRecord[]>(
      `sniper_health?select=unit,status,last_error,heartbeat_at,last_claim_at,last_guard_at,applied_config_version,updated_at&unit=eq.${encodeURIComponent(unit)}&limit=1`,
    );
    return rows[0] ?? null;
  }

  async listAudit(limit: number): Promise<AuditRecord[]> {
    return serviceJson<AuditRecord[]>(
      `sniper_audit?select=id,actor,action,target,before_hash,after_hash,result,detail,ip,created_at&order=created_at.desc&limit=${Math.max(1, Math.min(limit, 100))}`,
    );
  }

  async getAdmin(userId: string): Promise<AdminRecord | null> {
    const rows = await serviceJson<AdminRecord[]>(
      `sniper_admins?select=user_id,role,active&user_id=eq.${encodeURIComponent(userId)}&limit=1`,
    );
    return rows[0] ?? null;
  }

  async saveConfig(input: SaveConfigInput): Promise<ConfigRecord> {
    const result = await serviceJson<ConfigRecord | ConfigRecord[]>("rpc/sniper_save_config", {
      method: "POST",
      body: JSON.stringify({
        p_config: input.config,
        p_author: input.actor,
        p_note: input.note ?? null,
        p_ip: input.ip ?? null,
      }),
    });
    const row = one(result);
    if (!row) throw new Error("sniper_save_config returned no row");
    return row;
  }

  async appendAudit(entry: {
    actor: string | null;
    action: string;
    target?: string | null;
    result?: "ok" | "error";
    detail?: Record<string, unknown>;
    ip?: string | null;
  }): Promise<void> {
    await serviceRest("sniper_audit", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify([{
        actor: entry.actor,
        action: entry.action,
        target: entry.target ?? null,
        result: entry.result ?? "ok",
        detail: entry.detail ?? {},
        ip: entry.ip ?? null,
      }]),
    });
  }
}
