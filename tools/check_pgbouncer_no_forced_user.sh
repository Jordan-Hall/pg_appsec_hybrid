#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bad=0
while IFS= read -r f; do
  if rg -n '^\s*[^#]*\buser\s*=' "$f" | rg -v 'auth_user|admin_users|stats_users'; then
    echo "ERROR: forced user= found in $f (forbidden for appsec pooling)"
    bad=1
  fi
done < <(find "$root/config" -name 'pgbouncer*.ini' -print)
exit $bad
