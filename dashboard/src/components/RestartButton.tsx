"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function RestartButton({ enabled }: { enabled: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [isError, setIsError] = useState(false);

  async function restart() {
    if (!window.confirm("Restart discord-sniper.service now?")) return;
    setBusy(true);
    setMessage(null);
    setIsError(false);
    try {
      const response = await fetch("/api/restart", { method: "POST" });
      const body = (await response.json()) as { message?: string; output?: string };
      if (!response.ok) throw new Error(body.message ?? "Restart failed.");
      setMessage(body.output || "Restart helper completed.");
      router.refresh();
    } catch (error) {
      setIsError(true);
      setMessage(error instanceof Error ? error.message : "Restart failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack" style={{ gap: 6 }}>
      <button
        className="button danger"
        type="button"
        onClick={restart}
        disabled={!enabled || busy}
        title={enabled ? undefined : "DASHBOARD_HOST_ACTIONS is not enabled on this host"}
      >
        {busy ? "Restarting…" : "Restart sniper"}
      </button>
      {!enabled ? (
        <span className="small muted">
          Host actions disabled. Set <span className="mono">DASHBOARD_HOST_ACTIONS=1</span> to
          allow the fixed-unit helper.
        </span>
      ) : null}
      {message ? (
        <span className={isError ? "small notice error" : "small notice success"}>{message}</span>
      ) : null}
    </div>
  );
}
