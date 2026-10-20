import { DatastoreError } from "./errors";
import { FileStore } from "./file-store";
import { hasSupabaseServerConfig } from "./supabase";
import { SupabaseStore } from "./supabase-store";
import type { DashboardStore } from "./types";

let cached: DashboardStore | null = null;

export function resetStoreForTests(): void {
  cached = null;
}

export function getStore(): DashboardStore {
  if (cached) return cached;

  if (process.env.DASHBOARD_STORE === "file") {
    if (process.env.DASHBOARD_ALLOW_FILE_STORE !== "1") {
      console.error("[dashboard] file store requested without DASHBOARD_ALLOW_FILE_STORE=1");
      throw new DatastoreError("The dashboard file store is not enabled.");
    }
    cached = new FileStore(process.env.DASHBOARD_DATA_FILE ?? ".local/dashboard-data.json");
    return cached;
  }

  if (hasSupabaseServerConfig()) {
    cached = new SupabaseStore();
    return cached;
  }

  console.error("[dashboard] no datastore configured");
  throw new DatastoreError("The dashboard datastore is not configured.");
}

export const DASHBOARD_UNIT = process.env.SNIPER_UNIT ?? "discord-sniper.service";
