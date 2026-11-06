#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OV="$ROOT/oauth-validator"
NAME=${PG_OAUTH_CTR:-pg18-oauth-build}
ROLE=app_s_a1111111a111a111a111a11111111111

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker pull postgres:18
docker run --name "$NAME" -d --network host -e POSTGRES_PASSWORD=postgres postgres:18
for i in $(seq 1 60); do docker exec "$NAME" pg_isready -U postgres && break; sleep 1; done

docker exec "$NAME" bash -lc 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev postgresql-server-dev-18 libpq-dev'
docker cp "$OV" "$NAME:/tmp/oauth-validator"
docker exec "$NAME" bash -lc 'make -C /tmp/oauth-validator PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config && nm -D /tmp/oauth-validator/pg_appsec_oauth.so | grep _PG_oauth_validator_module_init && install -m 755 /tmp/oauth-validator/pg_appsec_oauth.so "$(pg_config --pkglibdir)/"'

python3 "$OV/mint_tokens.py"
docker cp "$OV/testdata" "$NAME:/tmp/testdata"
docker cp "$OV/oauth_client.c" "$NAME:/tmp/oauth_client.c"
docker exec "$NAME" bash -lc 'chmod -R a+rwX /tmp/testdata'

DATADIR=$(docker exec "$NAME" psql -U postgres -Atc "SHOW data_directory")
echo "DATADIR=$DATADIR"
docker exec "$NAME" bash -lc "touch '$DATADIR/jti_seen.txt' && chmod 666 '$DATADIR/jti_seen.txt'"

docker exec "$NAME" bash -lc "set -e
CONF=\$(psql -U postgres -Atc 'SHOW config_file')
HBA=\$(psql -U postgres -Atc 'SHOW hba_file')
grep -q pg_appsec_oauth \"\$CONF\" || cat >> \"\$CONF\" <<GUC
shared_preload_libraries = 'pg_appsec_oauth'
oauth_validator_libraries = 'pg_appsec_oauth'
pg_appsec.oauth_issuer = 'https://pg-appsec.test'
pg_appsec.oauth_audience = 'pg_appsec'
pg_appsec.oauth_required_scope = 'pg_appsec'
pg_appsec.oauth_pubkey_file = '/tmp/testdata/ed25519_public.pem'
pg_appsec.oauth_jwks_file = '/tmp/testdata/jwks_kid.json'
pg_appsec.oauth_session_state_file = '/tmp/testdata/session_state.json'
pg_appsec.oauth_jti_denylist_file = '${DATADIR}/jti_seen.txt'
pg_appsec.oauth_session_state_max_age_secs = 120
GUC
TMP=\$(mktemp)
{
  echo '# pg_appsec oauth e2e'
  echo 'host all all 127.0.0.1/32 oauth issuer=https://pg-appsec.test scope=pg_appsec validator=pg_appsec_oauth'
  echo 'host all all ::1/128 oauth issuer=https://pg-appsec.test scope=pg_appsec validator=pg_appsec_oauth'
  grep -E '^(local|host)' \"\$HBA\" | grep -v '127.0.0.1/32 oauth' | grep -v '::1/128 oauth' || true
} > \"\$TMP\"
cp \"\$TMP\" \"\$HBA\"
"
docker restart "$NAME"
for i in $(seq 1 60); do docker exec "$NAME" pg_isready -U postgres && break; sleep 1; done
# /tmp may be wiped; restore testdata and jti file
docker cp "$OV/testdata" "$NAME:/tmp/testdata"
docker exec "$NAME" bash -lc "chmod -R a+rwX /tmp/testdata; touch '$DATADIR/jti_seen.txt'; chmod 666 '$DATADIR/jti_seen.txt'"
PRELOAD=$(docker exec "$NAME" psql -U postgres -Atc "SHOW shared_preload_libraries")
echo "preload=$PRELOAD"
echo "$PRELOAD" | grep -q pg_appsec_oauth

docker exec "$NAME" psql -U postgres -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN CREATE ROLE $ROLE LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END \$\$;"

docker exec -e ROLE="$ROLE" -e DATADIR="$DATADIR" "$NAME" bash -lc 'set -e
cc -o /tmp/oauth_client /tmp/oauth_client.c -I$(pg_config --includedir) -L$(pg_config --libdir) -lpq
run_case() {
  local name=$1 token=$2 expect=$3
  set +e
  out=$(/tmp/oauth_client 127.0.0.1 5432 postgres "$ROLE" "$token" 2>&1)
  rc=$?
  set -e
  echo "$out"
  if [[ $expect == ok ]]; then
    [[ $rc -eq 0 ]] || { echo "FAIL $name expected ok"; exit 1; }
    echo "PASS $name"
  else
    [[ $rc -ne 0 ]] || { echo "FAIL $name expected deny"; exit 1; }
    echo "PASS $name (denied)"
  fi
}
TD=/tmp/testdata
run_case valid "$TD/token_valid.txt" ok
cp "$TD/session_state.json" "$TD/session_state.json.bak"
echo test-jti >> "$DATADIR/jti_seen.txt"
run_case jti_replay "$TD/token_valid.txt" fail
run_case badsig "$TD/token_badsig.txt" fail
run_case expired "$TD/token_expired.txt" fail
run_case wrong_aud "$TD/token_wrong_aud.txt" fail
run_case wrong_iss "$TD/token_wrong_iss.txt" fail
run_case wrong_role "$TD/token_wrong_role.txt" fail
run_case alg_none "$TD/token_alg_none.txt" fail
run_case kid_jwks "$TD/token_valid_kid.txt" ok
cp "$TD/session_state_revoked.json" "$TD/session_state.json"
run_case revoked_sid "$TD/token_revoked_sid.txt" fail
echo oauth_e2e_cases_done
'

# Host-side stale session-state + unique jti token
python3 - "$OV/testdata" <<'PYHOST'
import json, sys
from pathlib import Path
td = Path(sys.argv[1])
obj = json.loads((td / "session_state.json").read_text())
obj["generated_at"] = "2000-01-01T00:00:00Z"
(td / "session_state_stale.json").write_text(json.dumps(obj, separators=(",", ":")))
print("wrote stale session_state")
PYHOST
docker cp "$OV/testdata/session_state_stale.json" "$NAME:/tmp/testdata/session_state.json"
docker cp "$OV/testdata/token_stale_probe.txt" "$NAME:/tmp/testdata/token_stale_probe.txt"

docker exec -e ROLE="$ROLE" "$NAME" bash -lc 'set -e
run_case() {
  local name=$1 token=$2 expect=$3
  set +e
  out=$(/tmp/oauth_client 127.0.0.1 5432 postgres "$ROLE" "$token" 2>&1)
  rc=$?
  set -e
  echo "$out"
  if [[ $expect == ok ]]; then
    [[ $rc -eq 0 ]] || { echo "FAIL $name expected ok"; exit 1; }
    echo "PASS $name"
  else
    [[ $rc -ne 0 ]] || { echo "FAIL $name expected deny"; exit 1; }
    echo "PASS $name (denied)"
  fi
}
run_case stale_state /tmp/testdata/token_stale_probe.txt fail
echo oauth_e2e_matrix_ok
'
