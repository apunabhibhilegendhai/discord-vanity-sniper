"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export function SignInForm({ devMode }: { devMode: boolean }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [devToken, setDevToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(devMode ? { devToken } : { email, password }),
      });
      const body = (await response.json()) as { message?: string };
      if (!response.ok) throw new Error(body.message ?? "Sign-in failed.");
      router.replace("/");
      router.refresh();
    } catch (signInError) {
      setError(signInError instanceof Error ? signInError.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ maxWidth: 520, margin: "8vh auto 0" }}>
      <h1>Sign in</h1>
      <p className="lede">
        The dashboard validates your Supabase access token with the self-hosted{" "}
        <span className="mono">/auth/v1/user</span> endpoint. Only users listed in{" "}
        <span className="mono">sniper_admins</span> can read or change configuration.
      </p>
      {devMode ? (
        <div className="notice">
          Local development auth is enabled. Use the value of{" "}
          <span className="mono">DASHBOARD_DEV_TOKEN</span>; this mode is refused unless{" "}
          <span className="mono">DASHBOARD_ALLOW_DEV_AUTH=1</span> is set explicitly.
        </div>
      ) : null}
      <form className="stack" onSubmit={submit}>
        {devMode ? (
          <div className="field">
            <label htmlFor="dev-token">Development token</label>
            <input
              id="dev-token"
              type="password"
              autoComplete="current-password"
              value={devToken}
              onChange={(event) => setDevToken(event.target.value)}
              required
            />
          </div>
        ) : (
          <>
            <div className="field">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </div>
          </>
        )}
        {error ? <div className="notice error">{error}</div> : null}
        <button className="button primary" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
