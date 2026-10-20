import Link from "next/link";
import { SignInForm } from "@/components/SignInForm";
import { RestartButton } from "@/components/RestartButton";
import { Unavailable } from "@/components/Unavailable";
import { devAuthEnabled } from "@/lib/auth";
import { buildHealthView } from "@/lib/health";
import { getPageAuth } from "@/lib/page-auth";
import { DASHBOARD_UNIT, getStore } from "@/lib/store";
import type { AuditRecord, ConfigRecord, HealthView } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function formatTime(value: string | null): string {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().replace("T", " ").replace(".000Z", "Z");
}

function AccessDenied() {
  return (
    <div className="card" style={{ maxWidth: 640, margin: "8vh auto 0" }}>
      <h1>Not authorized</h1>
      <p className="lede">
        Your Supabase session is valid, but this account is not listed as an active
        administrator in <span className="mono">sniper_admins</span>.
      </p>
      <p className="muted">
        An operator must insert your <span className="mono">auth.users.id</span> once with the
        service-role key. Public sign-up never grants admin.
      </p>
    </div>
  );
}

export default async function OverviewPage() {
  const auth = await getPageAuth();
  if (auth.status === "anonymous") return <SignInForm devMode={devAuthEnabled()} />;
  if (auth.status === "unavailable") {
    return <Unavailable title={auth.title} message={auth.message} />;
  }
  if (auth.status === "denied") return <AccessDenied />;
  const session = auth.session;

  let config: ConfigRecord | null = null;
  let health: HealthView = buildHealthView(null);
  let audit: AuditRecord[] = [];

  try {
    const store = getStore();
    const [active, record, events] = await Promise.all([
      store.getActiveConfig(),
      store.getHealth(DASHBOARD_UNIT),
      store.listAudit(8),
    ]);
    config = active;
    health = buildHealthView(record, new Date(), active?.version ?? null);
    audit = events;
  } catch (error) {
    console.error("[dashboard] overview load failed", error);
    return (
      <Unavailable
        title="Status unavailable"
        message="The dashboard could not read its datastore. Health and config are not shown because they could not be verified."
      />
    );
  }

  const applied = health.appliedConfigVersion;
  return (
    <div className="stack">
      <div>
        <p className="small muted">SIGNED IN AS {session.email ?? session.id}</p>
        <h1>Overview</h1>
        <p className="lede">
          The dashboard reads sidecar health and versioned config. It does not inspect the
          sniper process directly, and it never receives the Discord token in the browser.
        </p>
      </div>

      {health.configDrift ? (
        <div className="notice error">
          Stored config v{config?.version ?? "?"} has not been applied; the sidecar reports
          v{health.appliedConfigVersion ?? "unknown"}. Check sniper-config-sync.
        </div>
      ) : null}

      <div className="grid">
        <section className="card span-8">
          <div className="row">
            <div>
              <p className="small muted">SNIPER SERVICE</p>
              <h2>{health.unit === "unknown" ? DASHBOARD_UNIT : health.unit}</h2>
            </div>
            <span className={`status ${health.state}`}>{health.state}</span>
          </div>
          <p>{health.message}</p>
          <div className="grid" style={{ gap: 10 }}>
            <div className="card span-4" style={{ background: "transparent" }}>
              <p className="small muted">Heartbeat</p>
              <p className="mono">{formatTime(health.heartbeatAt)}</p>
              <p className="small muted">
                {health.heartbeatAgeSeconds === null
                  ? "No heartbeat"
                  : `${health.heartbeatAgeSeconds}s old`}
              </p>
            </div>
            <div className="card span-4" style={{ background: "transparent" }}>
              <p className="small muted">Last error</p>
              <p className="mono">{health.lastError ?? "none recorded"}</p>
            </div>
            <div className="card span-4" style={{ background: "transparent" }}>
              <p className="small muted">Applied config</p>
              <p className="mono">
                {applied === null ? "unknown" : `v${applied}`}
                {config ? ` (stored v${config.version})` : ""}
              </p>
            </div>
          </div>
          <div className="actions" style={{ marginTop: 14 }}>
            <RestartButton enabled={process.env.DASHBOARD_HOST_ACTIONS === "1"} />
            <Link className="button" href="/issues">
              Inspect issues
            </Link>
          </div>
        </section>

        <section className="card span-4">
          <p className="small muted">ACTIVE CONFIG</p>
          <h2>{config ? `Version ${config.version}` : "Not configured"}</h2>
          <p className="muted">
            {config
              ? `${config.config.targets.length} target${config.config.targets.length === 1 ? "" : "s"} · saved ${formatTime(config.created_at)}`
              : "No active config row exists yet. Create one before enabling the config-sync timer."}
          </p>
          {config ? (
            <ul className="list">
              {config.config.targets.map((target) => (
                <li key={target.guild_id}>
                  <div className="mono">{target.vanity}</div>
                  <div className="small muted">guild {target.guild_id}</div>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="actions" style={{ marginTop: 14 }}>
            <Link className="button primary" href="/config">
              Edit config
            </Link>
          </div>
        </section>

        <section className="card span-12">
          <div className="row">
            <div>
              <p className="small muted">RECENT ACTIVITY</p>
              <h2>Audit trail</h2>
            </div>
            <Link href="/issues">All issues</Link>
          </div>
          {audit.length === 0 ? (
            <p className="muted">No audit events have been written yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((event) => (
                  <tr key={event.id}>
                    <td className="mono">{formatTime(event.created_at)}</td>
                    <td>{event.action}</td>
                    <td className="mono">{event.target ?? "—"}</td>
                    <td>{event.result}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </div>
  );
}
