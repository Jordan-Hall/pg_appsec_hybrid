#!/usr/bin/env bash
# Live PgBouncer E2E: per-session SCRAM via auth_query, TLS client+server,
# A/B isolation, revoke, DISCARD ALL leakage, pgbouncer_auth no table access.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORKDIR=$(mktemp -d)
NET=pgappsec-net
cleanup() {
  docker rm -f pgappsec-pg pgappsec-bouncer >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  sudo rm -rf "$WORKDIR" 2>/dev/null || rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

PG_IMG=${PG_IMG:-postgres:18}
PB_IMG=${PB_IMG:-edoburu/pgbouncer:latest}
AUTH_PASS='pb-auth-secret-ci-only-32chars!!'
ROLE_A=app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ROLE_B=app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
PASS_A='session-a-password-ci-32chars-min!!'
PASS_B='session-b-password-ci-32chars-min!!'
SID_A=a1111111-a111-a111-a111-a11111111111
SID_B=b2222222-b222-b222-b222-b22222222222
UID_A=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
UID_B=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
TENANT=11111111-1111-1111-1111-111111111111

docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null
docker rm -f pgappsec-pg pgappsec-bouncer >/dev/null 2>&1 || true

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORKDIR/server.key" -out "$WORKDIR/server.crt" \
  -days 1 -subj "/CN=pgappsec-pg" >/dev/null 2>&1
cp "$WORKDIR/server.crt" "$WORKDIR/ca.crt"
# Separate key copy for PgBouncer (readable by its container user)
cp "$WORKDIR/server.key" "$WORKDIR/bouncer.key"
chmod 644 "$WORKDIR/bouncer.key" "$WORKDIR/server.crt" "$WORKDIR/ca.crt"
# Postgres needs key 0600 owned by its uid (999 in official image)
chmod 600 "$WORKDIR/server.key"
sudo chown 999:999 "$WORKDIR/server.key" 2>/dev/null || chown 999:999 "$WORKDIR/server.key" 2>/dev/null || true

docker run -d --name pgappsec-pg --network "$NET" \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appsec_test \
  -v "$WORKDIR/server.crt:/var/lib/postgresql/server.crt:ro" \
  -v "$WORKDIR/server.key:/var/lib/postgresql/server.key:ro" \
  "$PG_IMG" \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/server.crt \
  -c ssl_key_file=/var/lib/postgresql/server.key

for i in $(seq 1 90); do
  docker exec pgappsec-pg pg_isready -U postgres -d appsec_test >/dev/null 2>&1 && \
    docker exec pgappsec-pg psql -U postgres -Atc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
docker exec pgappsec-pg pg_isready -U postgres -d appsec_test
SSL=$(docker exec pgappsec-pg psql -U postgres -Atc "SHOW ssl")
echo "ssl=$SSL"
[[ "$SSL" == "on" ]]
docker exec -e PGPASSWORD=postgres pgappsec-pg \
  psql "host=127.0.0.1 dbname=appsec_test user=postgres sslmode=require" -Atc "SELECT 1" >/dev/null

for f in sql/001_roles.sql sql/002_schema.sql sql/003_policies.sql \
         sql/004_identity_sessions_acl.sql sql/005_schema_security.sql \
         sql/006_custom_rls.sql sql/007_hardening.sql sql/008_secdefiner_audit_and_pool.sql \
         sql/009_close_remaining_risks.sql sql/010_least_privilege_owners.sql sql/011_state_sync_role.sql; do
  docker exec -i pgappsec-pg psql -U postgres -d appsec_test -v ON_ERROR_STOP=1 < "$ROOT/$f" >/dev/null
done

docker exec -i pgappsec-pg psql -U postgres -d appsec_test -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
  CREATE ROLE pgbouncer_auth LOGIN PASSWORD '$AUTH_PASS'
    NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN ALTER ROLE pgbouncer_auth PASSWORD '$AUTH_PASS';
END \$\$;
GRANT appsec_pool_auth TO pgbouncer_auth;
SET password_encryption = 'scram-sha-256';
-- Real mint path: non-superuser appsec_role_admin creates + hardens session roles.
SELECT appsec.create_session_role('$ROLE_A', '$PASS_A', now() + interval '1 day', 2);
SELECT appsec.create_session_role('$ROLE_B', '$PASS_B', now() + interval '1 day', 2);
SELECT appsec.harden_session_role('$ROLE_A', now() + interval '1 day', 2);
SELECT appsec.harden_session_role('$ROLE_B', now() + interval '1 day', 2);
INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES
 ('$TENANT','t1','T1','active') ON CONFLICT DO NOTHING;
INSERT INTO appsec.users(user_id,email,status,tenant_id) VALUES
 ('$UID_A','a@t1','active','$TENANT'),
 ('$UID_B','b@t1','active','$TENANT') ON CONFLICT DO NOTHING;
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method) VALUES
 ('$SID_A','$UID_A',now()+interval '1 day','password'),
 ('$SID_B','$UID_B',now()+interval '1 day','password')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL, expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role) VALUES
 ('$SID_A','$UID_A','$ROLE_A'), ('$SID_B','$UID_B','$ROLE_B')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;
INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier)
SELECT '$ROLE_A','$SID_A', rolpassword FROM pg_authid WHERE rolname='$ROLE_A'
ON CONFLICT (db_role) DO UPDATE SET scram_verifier=EXCLUDED.scram_verifier, revoked_at=NULL, session_id=EXCLUDED.session_id;
INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier)
SELECT '$ROLE_B','$SID_B', rolpassword FROM pg_authid WHERE rolname='$ROLE_B'
ON CONFLICT (db_role) DO UPDATE SET scram_verifier=EXCLUDED.scram_verifier, revoked_at=NULL, session_id=EXCLUDED.session_id;
INSERT INTO appsec.documents(document_id, tenant_id, owner_id, body) VALUES
  ('d1111111-1111-1111-1111-111111111111','$TENANT','$UID_A','{"k":"a"}'::jsonb),
  ('d2222222-2222-2222-2222-222222222222','$TENANT','$UID_B','{"k":"b"}'::jsonb)
ON CONFLICT DO NOTHING;
SQL

docker exec pgappsec-pg bash -lc '
HBA=$(psql -U postgres -Atc "SHOW hba_file")
{ echo "hostssl all all 0.0.0.0/0 scram-sha-256"; echo "hostssl all all ::/0 scram-sha-256"; echo "host all all all scram-sha-256"; cat "$HBA"; } > /tmp/hba
cp /tmp/hba "$HBA"
psql -U postgres -c "SELECT pg_reload_conf()" >/dev/null
'

printf '"pgbouncer_auth" "%s"\n' "$AUTH_PASS" > "$WORKDIR/userlist.txt"
chmod 644 "$WORKDIR/userlist.txt"

cat > "$WORKDIR/pgbouncer.ini" <<INI
[databases]
appsec_test = host=pgappsec-pg port=5432 dbname=appsec_test

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
pool_mode = transaction
auth_type = scram-sha-256
auth_user = pgbouncer_auth
auth_query = SELECT username, password FROM appsec.pgbouncer_lookup(\$1)
auth_file = /etc/pgbouncer/userlist.txt
server_tls_sslmode = require
server_tls_ca_file = /etc/pgbouncer/ca.crt
client_tls_sslmode = require
client_tls_cert_file = /etc/pgbouncer/server.crt
client_tls_key_file = /etc/pgbouncer/server.key
client_tls_ca_file = /etc/pgbouncer/ca.crt
server_reset_query = DISCARD ALL
server_reset_query_always = 1
max_client_conn = 100
default_pool_size = 2
INI

grep -E '^\s*user\s*=' "$WORKDIR/pgbouncer.ini" && { echo 'FAIL forced user='; exit 1; } || true
bash "$ROOT/tools/check_pgbouncer_no_forced_user.sh"

docker run -d --name pgappsec-bouncer --network "$NET" -p 16432:6432 \
  -v "$WORKDIR/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro" \
  -v "$WORKDIR/userlist.txt:/etc/pgbouncer/userlist.txt:ro" \
  -v "$WORKDIR/ca.crt:/etc/pgbouncer/ca.crt:ro" \
  -v "$WORKDIR/server.crt:/etc/pgbouncer/server.crt:ro" \
  -v "$WORKDIR/bouncer.key:/etc/pgbouncer/server.key:ro" \
  "$PB_IMG"

psql_via() {
  local user=$1 pass=$2
  shift 2
  PGPASSWORD="$pass" psql "host=127.0.0.1 port=16432 dbname=appsec_test user=$user sslmode=verify-ca sslrootcert=${WORKDIR}/ca.crt" -v ON_ERROR_STOP=1 "$@"
}

ready=0
for i in $(seq 1 40); do
  if PGPASSWORD="$PASS_A" psql "host=127.0.0.1 port=16432 dbname=appsec_test user=$ROLE_A sslmode=verify-ca sslrootcert=$WORKDIR/ca.crt" -Atc 'SELECT 1' >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
if [[ $ready -ne 1 ]]; then
  echo 'FAIL pgbouncer never accepted connections'
  PGPASSWORD="$PASS_A" psql "host=127.0.0.1 port=16432 dbname=appsec_test user=$ROLE_A sslmode=verify-ca sslrootcert=$WORKDIR/ca.crt" -Atc 'SELECT 1' 2>&1 || true
  docker logs pgappsec-bouncer 2>&1 | tail -40 || true
  docker logs pgappsec-pg 2>&1 | tail -20 || true
  exit 1
fi

echo '== A uid =='
UA=$(psql_via "$ROLE_A" "$PASS_A" -Atc "SELECT appsec.uid()")
[[ "$UA" == "$UID_A" ]] || { echo "FAIL A uid=$UA"; exit 1; }
echo PASS a_uid

echo '== B uid =='
UB=$(psql_via "$ROLE_B" "$PASS_B" -Atc "SELECT appsec.uid()")
[[ "$UB" == "$UID_B" ]] || { echo "FAIL B uid=$UB"; exit 1; }
echo PASS b_uid

AONLY=$(psql_via "$ROLE_A" "$PASS_A" -Atc "SELECT count(*) FROM appsec.documents WHERE owner_id='$UID_B'")
[[ "$AONLY" == "0" ]] || { echo "FAIL A saw B rows=$AONLY"; exit 1; }
echo PASS ab_isolation

echo '== pgbouncer_auth no data =='
set +e
OUT=$(docker exec -e PGPASSWORD="$AUTH_PASS" pgappsec-pg \
  psql -U pgbouncer_auth -d appsec_test -Atc "SELECT count(*) FROM appsec.documents" 2>&1)
RC=$?
set -e
[[ $RC -ne 0 ]] || { echo "FAIL pgbouncer_auth local read: $OUT"; exit 1; }
echo PASS pgbouncer_auth_no_data

echo '== DISCARD ALL =='
psql_via "$ROLE_A" "$PASS_A" -Atc "SELECT set_config('appsec._leak_probe','secret-a',false)" >/dev/null
LEAK=$(psql_via "$ROLE_B" "$PASS_B" -Atc "SELECT current_setting('appsec._leak_probe', true)")
[[ -z "$LEAK" ]] || { echo "FAIL GUC leaked: $LEAK"; exit 1; }
echo PASS discard_no_guc_leak

echo '== Revoke =='
docker exec -i pgappsec-pg psql -U postgres -d appsec_test -v ON_ERROR_STOP=1 <<SQL
UPDATE appsec.pool_credentials SET revoked_at=clock_timestamp() WHERE db_role='$ROLE_A';
UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE session_id='$SID_A';
ALTER ROLE $ROLE_A NOLOGIN;
SQL
set +e
psql_via "$ROLE_A" "$PASS_A" -Atc "SELECT 1" >/tmp/revoke_out 2>&1
RC=$?
set -e
[[ $RC -ne 0 ]] || { echo "FAIL revoked A connected"; cat /tmp/revoke_out; exit 1; }
echo PASS revoke_new_connect_denied

docker exec pgappsec-pg psql -U postgres -d appsec_test -c "ALTER ROLE $ROLE_A LOGIN" >/dev/null
UID_AFTER=$(docker exec -e PGPASSWORD="$PASS_A" pgappsec-pg \
  psql -U "$ROLE_A" -d appsec_test -Atc "SELECT appsec.uid() IS NULL")
[[ "$UID_AFTER" == "t" ]] || { echo "FAIL uid after revoke: $UID_AFTER"; exit 1; }
echo PASS revoked_existing_uid_null

echo pooler_e2e_matrix_ok
