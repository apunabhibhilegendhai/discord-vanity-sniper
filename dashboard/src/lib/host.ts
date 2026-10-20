import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { HttpError } from "./http";

const execFileAsync = promisify(execFile);

export function hostActionsEnabled(): boolean {
  return process.env.DASHBOARD_HOST_ACTIONS === "1";
}

/**
 * The dashboard runs as the `sniper` user. Its only privileged path is the
 * sudoers rule for /usr/local/sbin/sniper-restart, which restarts exactly
 * discord-sniper.service. No shell is involved, and no user input becomes an
 * argument.
 */
export async function restartSniper(): Promise<{ ok: true; output: string }> {
  if (!hostActionsEnabled()) {
    throw new HttpError(
      503,
      "host_actions_disabled",
      "Host actions are disabled. Set DASHBOARD_HOST_ACTIONS=1 on the host.",
    );
  }

  const helper = process.env.SNIPER_RESTART_HELPER ?? "/usr/local/sbin/sniper-restart";
  const sudo = process.env.SUDO_BIN ?? "/usr/bin/sudo";
  if (!helper.startsWith("/") || !sudo.startsWith("/")) {
    throw new HttpError(
      502,
      "restart_failed",
      "The restart helper is not configured on this host (paths must be absolute).",
    );
  }

  try {
    const { stdout, stderr } = await execFileAsync(sudo, ["-n", helper], {
      timeout: 20_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
    return { ok: true, output: `${stdout}${stderr}`.trim() };
  } catch (error) {
    console.error(
      "[dashboard] restart helper failed",
      error instanceof Error ? error.message : "unknown error",
    );
    throw new HttpError(
      502,
      "restart_failed",
      "The restart helper failed. Check the host logs for the unit state.",
    );
  }
}
