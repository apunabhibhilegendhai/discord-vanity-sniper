import { SignInForm } from "@/components/SignInForm";
import { Unavailable } from "@/components/Unavailable";
import { devAuthEnabled } from "@/lib/auth";
import { buildHealthView } from "@/lib/health";
import { getPageAuth } from "@/lib/page-auth";
import { DASHBOARD_UNIT, getStore } from "@/lib/store";
import type { AuditRecord, HealthView } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function formatTime(value: string | null): string {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().replace("T", " ").replace(".000Z", "Z");
}

export default async function IssuesPage() {
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

  let health: HealthView = buildHealthView(null);
  let audit: AuditRecord[] = [];
  try {
    const store = getStore();
    const [record, active, events] = await Promise.all([
      store.getHealth(DASHBOARD_UNIT),
      store.getActiveConfig(),
      store.listAudit(30),
    ]);
    health = buildHealthView(record, new Date(), active?.version ?? null);
    audit = events;
  } catch (error) {
    console.error("[dashboard] issues load failed", error);
    return (
      <Unavailable
        title="Issues unavailable"
        message="The dashboard could not read health or audit data, so no issue state can be shown."
      />
    );
  }

  return (
    <div className="stack">
      <div>
        <p className="small muted">HEALTH AND AUDIT</p>
        <h1>Issues</h1>
        <p className="lede">
          Health comes from the sidecar row written by <span className="mono">sniper-health</span>.
          A missing row means the dashboard cannot tell whether the process is alive; it does
          not mean the sniper is down.
        </p>
      </div>

      {health.configDrift ? (
        <div className="notice error">
          Stored config has not been applied; the sidecar reports v
          {health.appliedConfigVersion ?? "unknown"}. Check sniper-config-sync.
        </div>
      ) : null}

      <section className="card">
        <div className="row">
          <div>
            <p className="small muted">CURRENT STATE</p>
            <h2>Sidecar report</h2>
          </div>
          <span className={`status ${health.state}`}>{health.state}</span>
        </div>
        <p>{health.message}</p>
        <div className="grid" style={{ gap: 10 }}>
          <div className="card span-4" style={{ background: "transparent" }}>
            <p className="small muted">Last error</p>
            <pre>{health.lastError ?? "none recorded"}</pre>
          </div>
          <div className="card span-4" style={{ background: "transparent" }}>
            <p className="small muted">Last claim</p>
            <p className="mono">{formatTime(health.lastClaimAt)}</p>
          </div>
          <div className="card span-4" style={{ background: "transparent" }}>
            <p className="small muted">Last guard action</p>
            <p className="mono">{formatTime(health.lastGuardAt)}</p>
          </div>
        </div>
        <p className="small muted" style={{ marginTop: 12 }}>
          The sidecar cannot expose the Go process&apos;s in-memory latency ring or goroutine
          state; those remain operator-only.
        </p>
      </section>

      <section className="card">
        <p className="small muted">AUDIT TRAIL</p>
        <h2>Recent changes and restarts</h2>
        {audit.length === 0 ? (
          <p className="muted">No events yet.</p>
        ) : (
          <div className="stack">
            {audit.map((event) => (
              <article className="target-editor" key={event.id}>
                <div className="row">
                  <div>
                    <h3>{event.action}</h3>
                    <p className="small muted">
                      {formatTime(event.created_at)} · {event.actor ?? "system"} ·{" "}
                      {event.target ?? "—"}
                    </p>
                  </div>
                  <span className={event.result === "ok" ? "status ok" : "status degraded"}>
                    {event.result}
                  </span>
                </div>
                {Object.keys(event.detail ?? {}).length > 0 ? (
                  <pre>{JSON.stringify(event.detail, null, 2)}</pre>
                ) : null}
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
