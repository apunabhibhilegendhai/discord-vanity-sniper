import assert from "node:assert/strict";
import test from "node:test";
import { buildHealthView } from "../src/lib/health";
import type { HealthRecord } from "../src/lib/types";

const NOW = new Date("2026-10-20T12:00:00.000Z");

function record(overrides: Partial<HealthRecord> = {}): HealthRecord {
  return {
    unit: "discord-sniper.service",
    status: "active",
    last_error: null,
    heartbeat_at: "2026-10-20T11:59:30.000Z",
    last_claim_at: null,
    last_guard_at: null,
    applied_config_version: 3,
    updated_at: "2026-10-20T11:59:30.000Z",
    ...overrides,
  };
}

test("absent sidecar data is missing, not reported as down", () => {
  const view = buildHealthView(null, NOW);
  assert.equal(view.state, "missing");
  assert.match(view.message, /No health sidecar data/);
  assert.equal(view.appliedConfigVersion, null);
});

test("fresh active health is ok", () => {
  const view = buildHealthView(record(), NOW);
  assert.equal(view.state, "ok");
  assert.equal(view.heartbeatAgeSeconds, 30);
  assert.equal(view.appliedConfigVersion, 3);
  assert.equal(view.configDrift, false);
});

test("a stored version that differs from the applied version is drift", () => {
  const view = buildHealthView(record(), NOW, 4);
  assert.equal(view.state, "drift");
  assert.equal(view.configDrift, true);
  assert.match(view.message, /v4/);
  assert.match(view.message, /v3/);
});

test("matching stored and applied versions stay ok", () => {
  const view = buildHealthView(record(), NOW, 3);
  assert.equal(view.state, "ok");
  assert.equal(view.configDrift, false);
});

test("an unknown applied version is not reported as drift", () => {
  const view = buildHealthView(record({ applied_config_version: null }), NOW, 4);
  assert.equal(view.state, "ok");
  assert.equal(view.configDrift, false);
});

test("garbage health fields are degraded and never rendered raw", () => {
  const garbage = {
    ...record(),
    status: 42,
    last_error: { upstream: "raw body" },
    heartbeat_at: "not-a-date",
    last_claim_at: 123,
    applied_config_version: "garbage",
  } as unknown as HealthRecord;
  const view = buildHealthView(garbage, NOW, 4);
  assert.equal(view.state, "degraded");
  assert.equal(view.status, "unknown");
  assert.equal(view.heartbeatAt, null);
  assert.equal(view.lastError, null);
  assert.equal(view.lastClaimAt, null);
  assert.equal(view.appliedConfigVersion, null);
  assert.equal(view.configDrift, false);
  assert.match(view.message, /Malformed fields/);
});

test("a malformed last-error field alone cannot leave the row looking ok", () => {
  const garbage = { ...record(), last_error: { upstream: "raw body" } } as unknown as HealthRecord;
  const view = buildHealthView(garbage, NOW);
  assert.equal(view.state, "degraded");
  assert.equal(view.lastError, null);
  assert.match(view.message, /last_error/);
});

test("an old heartbeat is stale", () => {
  const view = buildHealthView(record({ heartbeat_at: "2026-10-20T11:50:00.000Z" }), NOW);
  assert.equal(view.state, "stale");
});

test("inactive or error-bearing service is degraded", () => {
  assert.equal(buildHealthView(record({ status: "inactive" }), NOW).state, "degraded");
  assert.equal(buildHealthView(record({ last_error: "gateway closed" }), NOW).state, "degraded");
});
