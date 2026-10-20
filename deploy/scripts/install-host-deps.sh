#!/usr/bin/env bash
# Check the tools the self-hosted deploy runner and host services need.
# This script does not install anything and does not modify the host.
set -euo pipefail

missing=0
for tool in git curl jq rsync node npm psql redis-cli gh systemctl journalctl sudo; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'ok   %s\n' "$tool"
  else
    printf 'MISS %s\n' "$tool"
    missing=1
  fi
done

if [ -x /usr/local/bin/cloudflared ]; then
  printf 'ok   /usr/local/bin/cloudflared\n'
else
  printf 'MISS /usr/local/bin/cloudflared\n'
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'EOF'

Install the missing packages before registering the runner. On Debian/Ubuntu,
the common packages are:
  sudo apt-get update
  sudo apt-get install -y curl jq rsync postgresql-client redis-tools nodejs npm
  # gh: https://github.com/cli/cli/blob/trunk/docs/install_linux.md
  # cloudflared: install the matching release asset at /usr/local/bin/cloudflared

The host also needs systemd (systemctl/journalctl), membership in the
systemd-journal group for journal reads, and a registered self-hosted runner
with the label `sniper-host`.
EOF
  exit 1
fi

echo "all host prerequisites present"
