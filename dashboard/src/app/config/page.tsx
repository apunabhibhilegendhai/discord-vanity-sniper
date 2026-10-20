import { SignInForm } from "@/components/SignInForm";
import { ConfigForm } from "@/components/ConfigForm";
import { Unavailable } from "@/components/Unavailable";
import { devAuthEnabled } from "@/lib/auth";
import { buildHealthView } from "@/lib/health";
import { getPageAuth } from "@/lib/page-auth";
import { DASHBOARD_UNIT, getStore } from "@/lib/store";
import { redactConfig, type SecretStatus } from "@/lib/validation";
import type { SniperConfig } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export default async function ConfigPage() {
  const auth = await getPageAuth();
  if (auth.status === "anonymous") return <SignInForm devMode={devAuthEnabled()} />;
  if (auth.status === "unavailable") {
    return <Unavailable title={auth.title} message={auth.message} />;
  }
  if (auth.status === "denied") {
    return (
      <div className="card" style={{ maxWidth: 640, margin: "8vh auto 0" }}>
        <h1>Not authorized</h1>
        <p className="lede">This account is not an active dashboard administrator.</p>
      </div>
    );
  }

  let initial: SniperConfig | null = null;
  let secretStatus: SecretStatus | null = null;
  let version: number | null = null;
  let appliedVersion: number | null = null;
  let configDrift = false;

  try {
    const store = getStore();
    const [active, health] = await Promise.all([
      store.getActiveConfig(),
      store.getHealth(DASHBOARD_UNIT),
    ]);
    if (active) {
      const redacted = redactConfig(active.config);
      initial = redacted.config;
      secretStatus = redacted.secretStatus;
      version = active.version;
    }
    const view = buildHealthView(health, new Date(), active?.version ?? null);
    appliedVersion = view.appliedConfigVersion;
    configDrift = view.configDrift;
  } catch (error) {
    console.error("[dashboard] config load failed", error);
    return (
      <Unavailable
        title="Config unavailable"
        message="The dashboard could not read the active config. Editing is disabled so an unknown state cannot be overwritten."
      />
    );
  }

  return (
    <div className="stack">
      <div>
        <p className="small muted">CONFIGURATION</p>
        <h1>Edit config</h1>
        <p className="lede">
          Edits are validated on the server and written as a new immutable version. Secret
          fields are never sent back to the browser; leave a secret blank to keep the current
          value, or tick Clear to remove it.
        </p>
      </div>
      {configDrift ? (
        <div className="notice error">
          Stored config v{version ?? "?"} has not been applied; the sidecar reports
          v{appliedVersion ?? "unknown"}. Check sniper-config-sync.
        </div>
      ) : null}
      <div className="notice">
        Active stored version: <span className="mono">{version ?? "none"}</span> · applied
        version reported by the sidecar:{" "}
        <span className="mono">{appliedVersion === null ? "unknown" : `v${appliedVersion}`}</span>.
        The host config-sync timer applies a new version within about 45 seconds.
      </div>
      <ConfigForm
        initial={initial}
        secretStatus={secretStatus}
        version={version}
      />
    </div>
  );
}
