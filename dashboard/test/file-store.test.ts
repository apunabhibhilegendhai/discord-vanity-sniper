import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileStore } from "../src/lib/file-store";
import type { SniperConfig } from "../src/lib/types";

const CONFIG: SniperConfig = {
  targets: [{ guild_id: "123456789012345678", vanity: "coolname", token: "token" }],
  burst_count: 5,
};

test("writes immutable versions, keeps one active config, and audits each save", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sniper-dashboard-"));
  const file = join(dir, "state.json");
  try {
    const store = new FileStore(file);
    assert.equal(await store.getActiveConfig(), null);

    const first = await store.saveConfig({
      config: CONFIG,
      actor: "00000000-0000-4000-8000-000000000001",
      note: "first",
    });
    assert.equal(first.version, 1);
    assert.equal((await store.getActiveConfig())?.version, 1);

    const second = await store.saveConfig({
      config: { ...CONFIG, burst_count: 7 },
      actor: "00000000-0000-4000-8000-000000000001",
      note: "second",
    });
    assert.equal(second.version, 2);
    assert.equal((await store.getActiveConfig())?.version, 2);
    assert.equal((await store.getActiveConfig())?.config.burst_count, 7);

    const audit = await store.listAudit(10);
    assert.equal(audit.length, 2);
    assert.equal(audit[0].detail.version, 2);

    const raw = JSON.parse(await readFile(file, "utf8"));
    assert.equal(raw.configs.filter((row: { active: boolean }) => row.active).length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("reads a seeded sidecar health row and returns null when absent", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sniper-dashboard-"));
  const file = join(dir, "state.json");
  try {
    await writeFile(file, JSON.stringify({
      configs: [],
      health: [{
        unit: "discord-sniper.service",
        status: "active",
        last_error: "timeout talking to gateway",
        heartbeat_at: new Date().toISOString(),
        last_claim_at: null,
        last_guard_at: null,
        applied_config_version: 4,
        updated_at: new Date().toISOString(),
      }],
      audit: [],
      admins: [],
    }), "utf8");
    const store = new FileStore(file);
    const health = await store.getHealth("discord-sniper.service");
    assert.equal(health?.status, "active");
    assert.equal(health?.applied_config_version, 4);
    assert.equal(await store.getHealth("other.service"), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
