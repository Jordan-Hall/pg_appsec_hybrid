#!/usr/bin/env bash
# Build validator + oauth_client, configure a local PG18, run token matrix.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OV="$ROOT/oauth-validator"
PG_CONFIG=${PG_CONFIG:-pg_config}
PGHOST=${PGHOST:-127.0.0.1}
PGPORT=${PGPORT:-5432}
PGUSER=${PGUSER:-postgres}
PGPASSWORD=${PGPASSWORD:-postgres}
export PGHOST PGPORT PGUSER PGPASSWORD

echo "== building validator =="
make -C "$OV" clean || true
make -C "$OV" PG_CONFIG="$PG_CONFIG"
PKGLIB=$("$PG_CONFIG" --pkglibdir)
sudo cp "$OV/pg_appsec_oauth.so" "$PKGLIB/"

echo "== generating keys/tokens =="
python3 "$OV/mint_tokens.py"

echo "== ensure role =="
ROLE=app_s_a1111111a111a111a111a11111111111
psql -d postgres -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
  CREATE ROLE $ROLE LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END \$\$;
SQL

echo "== building oauth_client =="
cc -o "$OV/oauth_client" "$OV/oauth_client.c" -I"$("$PG_CONFIG" --includedir)" -lpq

run_case() {
  local name=$1 token=$2 expect=$3
  set +e
  out=$("$OV/oauth_client" "$PGHOST" "$PGPORT" postgres "$ROLE" "$token" 2>&1)
  rc=$?
  set -e
  if [[ $expect == ok ]]; then
    [[ $rc -eq 0 ]] || { echo "FAIL $name expected ok: $out"; exit 1; }
    echo "PASS $name"
  else
    [[ $rc -ne 0 ]] || { echo "FAIL $name expected fail: $out"; exit 1; }
    echo "PASS $name (denied)"
  fi
}

run_case valid "$OV/testdata/token_valid.txt" ok
run_case badsig "$OV/testdata/token_badsig.txt" fail
run_case expired "$OV/testdata/token_expired.txt" fail
run_case wrong_aud "$OV/testdata/token_wrong_aud.txt" fail
run_case wrong_iss "$OV/testdata/token_wrong_iss.txt" fail
run_case wrong_role "$OV/testdata/token_wrong_role.txt" fail
run_case alg_none "$OV/testdata/token_alg_none.txt" fail
echo "oauth_e2e_matrix_ok"
