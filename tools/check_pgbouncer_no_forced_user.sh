#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bad=0
while IFS= read -r f; do
  if grep -E '^\s*[^#]*\buser\s*=' "$f" | grep -Ev 'auth_user|admin_users|stats_users' >/dev/null; then
    echo "ERROR: forced user= found in $f (forbidden for appsec pooling)"
    bad=1
  fi
done < <(find "$root/config" -name 'pgbouncer*.ini' -print)
exit $bad
