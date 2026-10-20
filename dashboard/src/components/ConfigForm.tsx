"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import type { SniperConfig, TargetConfig } from "@/lib/types";
import type { SecretStatus } from "@/lib/validation";

interface TargetDraft {
  guild_id: string;
  vanity: string;
  token: string;
  password: string;
  proxies: string;
  tokenSet: boolean;
  passwordSet: boolean;
  clearToken: boolean;
  clearPassword: boolean;
}

interface Props {
  initial: SniperConfig | null;
  secretStatus: SecretStatus | null;
  version: number | null;
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function ids(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function targetDrafts(initial: SniperConfig | null, secrets: SecretStatus | null): TargetDraft[] {
  if (!initial?.targets.length) {
    return [{
      guild_id: "",
      vanity: "",
      token: "",
      password: "",
      proxies: "",
      tokenSet: false,
      passwordSet: false,
      clearToken: false,
      clearPassword: false,
    }];
  }
  return initial.targets.map((target) => ({
    guild_id: target.guild_id ?? "",
    vanity: target.vanity ?? "",
    token: "",
    password: "",
    proxies: (target.proxies ?? []).join("\n"),
    tokenSet: Boolean(secrets?.targets?.[target.guild_id]?.token),
    passwordSet: Boolean(secrets?.targets?.[target.guild_id]?.password),
    clearToken: false,
    clearPassword: false,
  }));
}

export function ConfigForm({ initial, secretStatus, version }: Props) {
  const router = useRouter();
  const [targets, setTargets] = useState<TargetDraft[]>(() => targetDrafts(initial, secretStatus));
  const [email, setEmail] = useState(initial?.email ?? "");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookSet, setWebhookSet] = useState(Boolean(secretStatus?.webhook_url));
  const [clearWebhook, setClearWebhook] = useState(false);
  const [password, setPassword] = useState("");
  const [passwordSet, setPasswordSet] = useState(Boolean(secretStatus?.password));
  const [clearPassword, setClearPassword] = useState(false);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpSet, setTotpSet] = useState(Boolean(secretStatus?.totp_secret));
  const [clearTotp, setClearTotp] = useState(false);
  const [backupCodes, setBackupCodes] = useState("");
  const [backupCount, setBackupCount] = useState(secretStatus?.backup_codes ?? 0);
  const [clearBackupCodes, setClearBackupCodes] = useState(false);
  const [burstCount, setBurstCount] = useState(String(initial?.burst_count ?? 5));
  const [warmConnections, setWarmConnections] = useState(String(initial?.warm_connections ?? 5));
  const [sessionPath, setSessionPath] = useState(initial?.session_path ?? "session_state.json");
  const [guardMode, setGuardMode] = useState(Boolean(initial?.guard_mode));
  const [guardAction, setGuardAction] = useState(initial?.guard_action ?? "reclaim_only");
  const [guardReclaimMax, setGuardReclaimMax] = useState(String(initial?.guard_reclaim_max ?? 5));
  const [guardBackoff, setGuardBackoff] = useState(String(initial?.guard_reclaim_backoff_ms ?? 500));
  const [protectedIds, setProtectedIds] = useState((initial?.guard_protected_user_ids ?? []).join("\n"));
  const [browser, setBrowser] = useState(initial?.browser ?? "chrome");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [message, setMessage] = useState<string | null>(null);

  function updateTarget(index: number, patch: Partial<TargetDraft>) {
    setTargets((current) => current.map((target, i) => (i === index ? { ...target, ...patch } : target)));
  }

  function addTarget() {
    setTargets((current) => [...current, {
      guild_id: "",
      vanity: "",
      token: "",
      password: "",
      proxies: "",
      tokenSet: false,
      passwordSet: false,
      clearToken: false,
      clearPassword: false,
    }]);
  }

  function removeTarget(index: number) {
    setTargets((current) => current.length === 1 ? current : current.filter((_, i) => i !== index));
  }

  function buildConfig(): SniperConfig {
    const builtTargets: TargetConfig[] = targets.map((target) => {
      const value: TargetConfig = {
        guild_id: target.guild_id.trim(),
        vanity: target.vanity.trim(),
      };
      const proxyList = lines(target.proxies);
      if (proxyList.length > 0) value.proxies = proxyList;
      if (target.clearToken) value.token = "";
      else if (target.token) value.token = target.token;
      if (target.clearPassword) value.password = "";
      else if (target.password) value.password = target.password;
      return value;
    });

    const config: SniperConfig = {
      targets: builtTargets,
      email: email.trim(),
      burst_count: Number(burstCount),
      warm_connections: Number(warmConnections),
      session_path: sessionPath.trim(),
      guard_mode: guardMode,
      guard_action: guardAction as SniperConfig["guard_action"],
      guard_reclaim_max: Number(guardReclaimMax),
      guard_reclaim_backoff_ms: Number(guardBackoff),
      guard_protected_user_ids: ids(protectedIds),
      browser: browser as SniperConfig["browser"],
    };

    if (clearWebhook) config.webhook_url = "";
    else if (webhookUrl) config.webhook_url = webhookUrl;
    if (clearPassword) config.password = "";
    else if (password) config.password = password;
    if (clearTotp) config.totp_secret = "";
    else if (totpSecret) config.totp_secret = totpSecret;
    if (clearBackupCodes) config.backup_codes = [];
    else {
      const codes = lines(backupCodes);
      if (codes.length > 0) config.backup_codes = codes;
    }
    if (initial?.fingerprint) config.fingerprint = initial.fingerprint;
    return config;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setErrors([]);
    setMessage(null);
    try {
      const response = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config: buildConfig(), note }),
      });
      const body = (await response.json()) as {
        message?: string;
        details?: unknown;
        version?: number;
        secretStatus?: SecretStatus;
      };
      if (!response.ok) {
        const detail = Array.isArray(body.details)
          ? body.details.filter((value): value is string => typeof value === "string")
          : [];
        setErrors(detail.length > 0 ? detail : [body.message ?? "The config was not written."]);
        return;
      }
      setMessage(`Saved version ${body.version ?? "new"}. The host config-sync timer will apply it.`);
      if (body.secretStatus) {
        setWebhookSet(body.secretStatus.webhook_url);
        setPasswordSet(body.secretStatus.password);
        setTotpSet(body.secretStatus.totp_secret);
        setBackupCount(body.secretStatus.backup_codes);
        setTargets((current) => current.map((target) => {
          const status = body.secretStatus?.targets?.[target.guild_id];
          return {
            ...target,
            token: "",
            password: "",
            clearToken: false,
            clearPassword: false,
            tokenSet: Boolean(status?.token),
            passwordSet: Boolean(status?.password),
          };
        }));
      }
      setWebhookUrl("");
      setPassword("");
      setTotpSecret("");
      setBackupCodes("");
      setClearWebhook(false);
      setClearPassword(false);
      setClearTotp(false);
      setClearBackupCodes(false);
      router.refresh();
    } catch (error) {
      setErrors([error instanceof Error ? error.message : "The config was not written."]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="stack" onSubmit={submit}>
      <section className="card">
        <div className="row">
          <div>
            <p className="small muted">TARGETS</p>
            <h2>Guilds and vanities</h2>
          </div>
          <button className="button" type="button" onClick={addTarget}>Add target</button>
        </div>
        <div className="stack">
          {targets.map((target, index) => (
            <div className="target-editor stack" key={index}>
              <div className="row">
                <h3>Target {index + 1}</h3>
                <button
                  className="button danger"
                  type="button"
                  onClick={() => removeTarget(index)}
                  disabled={targets.length === 1}
                >
                  Remove
                </button>
              </div>
              <div className="form-grid">
                <div className="field">
                  <label htmlFor={`guild-${index}`}>Guild id</label>
                  <input
                    id={`guild-${index}`}
                    value={target.guild_id}
                    onChange={(event) => updateTarget(index, { guild_id: event.target.value })}
                    placeholder="123456789012345678"
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor={`vanity-${index}`}>Vanity</label>
                  <input
                    id={`vanity-${index}`}
                    value={target.vanity}
                    onChange={(event) => updateTarget(index, { vanity: event.target.value })}
                    placeholder="coolname"
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor={`token-${index}`}>Discord token</label>
                  <input
                    id={`token-${index}`}
                    type="password"
                    value={target.token}
                    onChange={(event) => updateTarget(index, { token: event.target.value, clearToken: false })}
                    placeholder={target.tokenSet ? "configured — leave blank to keep" : "user token"}
                    autoComplete="off"
                  />
                  {target.tokenSet ? (
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={target.clearToken}
                        onChange={(event) => updateTarget(index, {
                          clearToken: event.target.checked,
                          token: event.target.checked ? "" : target.token,
                        })}
                      />
                      Clear stored token
                    </label>
                  ) : null}
                </div>
                <div className="field">
                  <label htmlFor={`target-password-${index}`}>Target password (optional)</label>
                  <input
                    id={`target-password-${index}`}
                    type="password"
                    value={target.password}
                    onChange={(event) => updateTarget(index, { password: event.target.value, clearPassword: false })}
                    placeholder={target.passwordSet ? "configured — leave blank to keep" : "optional"}
                    autoComplete="off"
                  />
                  {target.passwordSet ? (
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={target.clearPassword}
                        onChange={(event) => updateTarget(index, {
                          clearPassword: event.target.checked,
                          password: event.target.checked ? "" : target.password,
                        })}
                      />
                      Clear stored password
                    </label>
                  ) : null}
                </div>
              </div>
              <div className="field">
                <label htmlFor={`proxies-${index}`}>Proxies (one per line, blank means direct)</label>
                <textarea
                  id={`proxies-${index}`}
                  value={target.proxies}
                  onChange={(event) => updateTarget(index, { proxies: event.target.value })}
                  placeholder="http://user:pass@host:port&#10;socks5://host:port"
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <p className="small muted">ACCOUNT AND SECRETS</p>
        <h2>Login recovery</h2>
        <p className="muted">
          A token is preferred. If a target has no token, global email plus this password (or
          the target password) lets the Go binary mint one at startup.
        </p>
        <div className="form-grid">
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="account-password">Global password</label>
            <input
              id="account-password"
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setClearPassword(false);
              }}
              placeholder={passwordSet ? "configured — leave blank to keep" : "optional"}
              autoComplete="off"
            />
            {passwordSet ? (
              <label className="check">
                <input
                  type="checkbox"
                  checked={clearPassword}
                  onChange={(event) => {
                    setClearPassword(event.target.checked);
                    if (event.target.checked) setPassword("");
                  }}
                />
                Clear stored password
              </label>
            ) : null}
          </div>
          <div className="field">
            <label htmlFor="totp">TOTP secret</label>
            <input
              id="totp"
              type="password"
              value={totpSecret}
              onChange={(event) => {
                setTotpSecret(event.target.value);
                setClearTotp(false);
              }}
              placeholder={totpSet ? "configured — leave blank to keep" : "base32 secret"}
              autoComplete="off"
            />
            {totpSet ? (
              <label className="check">
                <input
                  type="checkbox"
                  checked={clearTotp}
                  onChange={(event) => {
                    setClearTotp(event.target.checked);
                    if (event.target.checked) setTotpSecret("");
                  }}
                />
                Clear stored TOTP secret
              </label>
            ) : null}
          </div>
          <div className="field">
            <label htmlFor="webhook">Discord webhook URL</label>
            <input
              id="webhook"
              type="url"
              value={webhookUrl}
              onChange={(event) => {
                setWebhookUrl(event.target.value);
                setClearWebhook(false);
              }}
              placeholder={webhookSet ? "configured — leave blank to keep" : "https://discord.com/api/webhooks/…"}
              autoComplete="off"
            />
            {webhookSet ? (
              <label className="check">
                <input
                  type="checkbox"
                  checked={clearWebhook}
                  onChange={(event) => {
                    setClearWebhook(event.target.checked);
                    if (event.target.checked) setWebhookUrl("");
                  }}
                />
                Clear stored webhook
              </label>
            ) : null}
          </div>
        </div>
        <div className="field">
          <label htmlFor="backup-codes">
            Backup codes (one per line{backupCount ? `; ${backupCount} currently stored` : ""})
          </label>
          <textarea
            id="backup-codes"
            value={backupCodes}
            onChange={(event) => {
              setBackupCodes(event.target.value);
              setClearBackupCodes(false);
            }}
            placeholder="leave blank to keep existing codes"
          />
          {backupCount ? (
            <label className="check">
              <input
                type="checkbox"
                checked={clearBackupCodes}
                onChange={(event) => {
                  setClearBackupCodes(event.target.checked);
                  if (event.target.checked) setBackupCodes("");
                }}
              />
              Clear stored backup codes
            </label>
          ) : null}
        </div>
      </section>

      <section className="card">
        <p className="small muted">CLAIM AND GUARD</p>
        <h2>Runtime behavior</h2>
        <div className="form-grid">
          <div className="field">
            <label htmlFor="burst">Burst count</label>
            <input id="burst" type="number" min="1" max="50" value={burstCount} onChange={(event) => setBurstCount(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="warm">Warm connections</label>
            <input id="warm" type="number" min="1" max="50" value={warmConnections} onChange={(event) => setWarmConnections(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="session">Session state path</label>
            <input id="session" value={sessionPath} onChange={(event) => setSessionPath(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="browser">Browser fingerprint</label>
            <select id="browser" value={browser} onChange={(event) => setBrowser(event.target.value as "chrome" | "firefox")}>
              <option value="chrome">Chrome</option>
              <option value="firefox">Firefox</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="guard-action">Guard action</label>
            <select id="guard-action" value={guardAction} onChange={(event) => setGuardAction(event.target.value as typeof guardAction)}>
              <option value="reclaim_only">Reclaim only</option>
              <option value="kick">Kick offender</option>
              <option value="ban">Ban offender</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="guard-max">Guard reclaim max</label>
            <input id="guard-max" type="number" min="1" max="20" value={guardReclaimMax} onChange={(event) => setGuardReclaimMax(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="guard-backoff">Guard backoff (ms)</label>
            <input id="guard-backoff" type="number" min="0" max="60000" value={guardBackoff} onChange={(event) => setGuardBackoff(event.target.value)} />
          </div>
          <div className="field">
            <label className="check" htmlFor="guard-mode" style={{ paddingTop: 24 }}>
              <input id="guard-mode" type="checkbox" checked={guardMode} onChange={(event) => setGuardMode(event.target.checked)} />
              Enable Vanity Guard
            </label>
          </div>
        </div>
        <div className="field">
          <label htmlFor="protected-ids">Protected user ids (one per line or comma separated)</label>
          <textarea id="protected-ids" value={protectedIds} onChange={(event) => setProtectedIds(event.target.value)} />
        </div>
      </section>

      <section className="card">
        <div className="field">
          <label htmlFor="note">Change note (optional, written to the audit row)</label>
          <input id="note" value={note} onChange={(event) => setNote(event.target.value)} maxLength={500} />
        </div>
        {errors.length > 0 ? (
          <div className="notice error">
            <strong>Not written.</strong>
            <ul>{errors.map((error) => <li key={error}>{error}</li>)}</ul>
          </div>
        ) : null}
        {message ? <div className="notice success">{message}</div> : null}
        <div className="actions">
          <button className="button primary" type="submit" disabled={busy}>
            {busy ? "Validating…" : version ? "Save new version" : "Create config"}
          </button>
          <span className="small muted">Secrets are never rendered back into this page.</span>
        </div>
      </section>
    </form>
  );
}
