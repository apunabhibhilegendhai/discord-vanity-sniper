import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { DatastoreError } from "./errors";
import type {
  AdminRecord,
  AuditRecord,
  ConfigRecord,
  DashboardStore,
  HealthRecord,
  SaveConfigInput,
} from "./types";

interface FileState {
  configs: ConfigRecord[];
  health: HealthRecord[];
  audit: AuditRecord[];
  admins: AdminRecord[];
}

function emptyState(): FileState {
  return { configs: [], health: [], audit: [], admins: [] };
}

function isState(value: unknown): value is FileState {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    Array.isArray(record.configs) &&
    Array.isArray(record.health) &&
    Array.isArray(record.audit) &&
    Array.isArray(record.admins)
  );
}

export class FileStore implements DashboardStore {
  private readonly path: string;

  constructor(path: string) {
    this.path = resolve(path);
  }

  private async readState(): Promise<FileState> {
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed: unknown = JSON.parse(raw);
      if (!isState(parsed)) throw new Error(`Invalid dashboard data file: ${this.path}`);
      return parsed;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      console.error(
        "[dashboard] data file read failed",
        (error as NodeJS.ErrnoException).code ?? "parse_error",
      );
      throw new DatastoreError("The dashboard data file is unreadable or corrupt.");
    }
  }

  private async writeState(state: FileState): Promise<void> {
    try {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      const tmp = `${this.path}.${randomUUID()}.tmp`;
      await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
      await chmod(tmp, 0o600);
      await rename(tmp, this.path);
    } catch (error) {
      console.error("[dashboard] data file write failed", (error as NodeJS.ErrnoException).code);
      throw new DatastoreError("The dashboard data file could not be written.");
    }
  }

  async getActiveConfig(): Promise<ConfigRecord | null> {
    const state = await this.readState();
    return state.configs.find((config) => config.active) ?? null;
  }

  async getHealth(unit: string): Promise<HealthRecord | null> {
    const state = await this.readState();
    return state.health.find((row) => row.unit === unit) ?? null;
  }

  async listAudit(limit: number): Promise<AuditRecord[]> {
    const state = await this.readState();
    return [...state.audit]
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
      .slice(0, Math.max(1, Math.min(limit, 100)));
  }

  async getAdmin(userId: string): Promise<AdminRecord | null> {
    const state = await this.readState();
    return state.admins.find((admin) => admin.user_id === userId) ?? null;
  }

  async saveConfig(input: SaveConfigInput): Promise<ConfigRecord> {
    const state = await this.readState();
    const version = state.configs.reduce((max, row) => Math.max(max, row.version), 0) + 1;
    const record: ConfigRecord = {
      id: randomUUID(),
      version,
      active: true,
      config: input.config,
      author: input.actor,
      note: input.note ?? null,
      created_at: new Date().toISOString(),
    };
    for (const row of state.configs) row.active = false;
    state.configs.push(record);
    state.audit.push({
      id: randomUUID(),
      actor: input.actor,
      action: "config.save",
      target: "sniper_configs",
      before_hash: null,
      after_hash: null,
      result: "ok",
      detail: { version },
      ip: input.ip ?? null,
      created_at: new Date().toISOString(),
    });
    await this.writeState(state);
    return record;
  }

  async appendAudit(entry: {
    actor: string | null;
    action: string;
    target?: string | null;
    result?: "ok" | "error";
    detail?: Record<string, unknown>;
    ip?: string | null;
  }): Promise<void> {
    const state = await this.readState();
    state.audit.push({
      id: randomUUID(),
      actor: entry.actor,
      action: entry.action,
      target: entry.target ?? null,
      before_hash: null,
      after_hash: null,
      result: entry.result ?? "ok",
      detail: entry.detail ?? {},
      ip: entry.ip ?? null,
      created_at: new Date().toISOString(),
    });
    await this.writeState(state);
  }
}
