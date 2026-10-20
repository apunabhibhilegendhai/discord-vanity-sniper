import assert from "node:assert/strict";
import test from "node:test";
import { mergeSecretFields, redactConfig, validateConfig } from "../src/lib/validation";
import type { SniperConfig } from "../src/lib/types";

function validConfig(): SniperConfig {
  return {
    targets: [{
      guild_id: "123456789012345678",
      vanity: "coolname",
      token: "discord-token-value",
      proxies: [""],
    }],
    burst_count: 5,
    warm_connections: 5,
    guard_mode: true,
    guard_action: "reclaim_only",
    guard_reclaim_max: 5,
    guard_reclaim_backoff_ms: 500,
    email: "operator@example.com",
    browser: "chrome",
  };
}

test("accepts a valid config and keeps the fields the Go loader expects", () => {
  const result = validateConfig(validConfig());
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.targets[0].guild_id, "123456789012345678");
  assert.equal(result.value.targets[0].token, "discord-token-value");
  assert.equal(result.value.burst_count, 5);
});

test("rejects a typo instead of silently dropping it", () => {
  const bad = { ...validConfig(), guard_acton: "kick" };
  const result = validateConfig(bad);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.errors.some((error) => error.includes("guard_acton")));
});

test("rejects a target with no token and no login path", () => {
  const bad = validConfig();
  bad.targets[0].token = "";
  bad.email = "";
  const result = validateConfig(bad);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.errors.some((error) => error.includes("email is required")));
});

test("rejects duplicate guild ids and malformed vanities", () => {
  const bad = validConfig();
  bad.targets.push({ ...bad.targets[0], vanity: "bad vanity!" });
  const result = validateConfig(bad);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.errors.some((error) => error.includes("duplicated")));
  assert.ok(result.errors.some((error) => error.includes("vanity")));
});

test("absent secrets are preserved; an explicit empty string clears them", () => {
  const current = validConfig();
  current.webhook_url = "https://discord.com/api/webhooks/123/abc";
  current.totp_secret = "JBSWY3DPEHPK3PXP";
  const incoming: SniperConfig = {
    ...validConfig(),
    targets: [{ guild_id: "123456789012345678", vanity: "coolname" }],
  };
  const merged = mergeSecretFields(incoming, current);
  assert.equal(merged.targets[0].token, "discord-token-value");
  assert.equal(merged.webhook_url, current.webhook_url);
  assert.equal(merged.totp_secret, current.totp_secret);

  const cleared = mergeSecretFields({
    ...incoming,
    targets: [{ guild_id: "123456789012345678", vanity: "coolname", token: "" }],
    webhook_url: "",
  }, current);
  assert.equal(cleared.targets[0].token, "");
  assert.equal(cleared.webhook_url, "");
});

test("redaction removes every secret field and reports presence only", () => {
  const config = validConfig();
  config.webhook_url = "https://discord.com/api/webhooks/123/abc";
  config.password = "secret";
  config.totp_secret = "JBSWY3DPEHPK3PXP";
  config.backup_codes = ["one", "two"];
  const { config: redacted, secretStatus } = redactConfig(config);
  assert.equal(redacted.webhook_url, undefined);
  assert.equal(redacted.password, undefined);
  assert.equal(redacted.totp_secret, undefined);
  assert.equal(redacted.backup_codes, undefined);
  assert.equal(redacted.targets[0].token, undefined);
  assert.equal(secretStatus.webhook_url, true);
  assert.equal(secretStatus.password, true);
  assert.equal(secretStatus.totp_secret, true);
  assert.equal(secretStatus.backup_codes, 2);
  assert.equal(secretStatus.targets["123456789012345678"].token, true);
});
