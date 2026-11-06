#!/usr/bin/env bash
# Phase 2 of the OAuth E2E (runs after ci_docker_e2e.sh in the same container):
#  A. strict session-state parser (malformed / trailing / unknown key /
#     substring confusion / escapes / oversized / missing generated_at)
#  B. jti file pruning by exp + size cap fail-closed
#  C. live oauth-state-sync worker: revoke -> denied within 5s; kill worker
#     -> fail closed after max-age; restart -> recovers
#  D. Ed25519-signed audit checkpoints: verify OK, signature tamper and
#     superuser history rewrite detected
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OV="$ROOT/oauth-validator"
NAME=${PG_OAUTH_CTR:-pg18-oauth-build}
BIN=${OAUTH_SYNC_BIN:-$ROOT/target/release/oauth-state-sync}
ROLE=app_s_a1111111a111a111a111a11111111111
SID=a1111111-a111-a111-a111-a11111111111
TD=/tmp/testdata
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
[[ -x $BIN ]] || { echo "missing worker binary $BIN"; exit 1; }

DATADIR=$(docker exec "$NAME" psql -U postgres -Atc "SHOW data_directory")
STATE="$DATADIR/sync/session_state.json"
JTI="$DATADIR/jti_seen.txt"
psqlc() { docker exec -i "$NAME" psql -U postgres -v ON_ERROR_STOP=1 -Atq "$@"; }
gucset() { psqlc -c "ALTER SYSTEM SET $1 = '$2'" -c "SELECT pg_reload_conf()" >/dev/null; sleep 1; }
gucreset() { psqlc -c "ALTER SYSTEM RESET $1" -c "SELECT pg_reload_conf()" >/dev/null; sleep 1; }

# Re-copy fresh tokens (minted by ci_docker_e2e.sh) into the container.
docker exec "$NAME" bash -lc "mkdir -p '$DATADIR/sync' && chown postgres:postgres '$DATADIR/sync' && chmod 700 '$DATADIR/sync'"
docker cp "$OV/testdata/." "$NAME:$TD/"
docker exec "$NAME" bash -lc "chmod -R a+rX $TD"

NEXT=1
# Sets $TOK (no subshell, so the counter advances).
next_token() { TOK="$TD/token_p${NEXT}.txt"; NEXT=$((NEXT + 1)); }
try_login() { docker exec "$NAME" /tmp/oauth_client 127.0.0.1 5432 postgres "$ROLE" "$1" >/dev/null 2>&1; }
expect() {
  local name=$1 want=$2
  next_token
  if try_login "$TOK"; then got=ok; else got=fail; fi
  echo "  ($name used $(basename "$TOK"))"
  [[ $got == "$want" ]] || { echo "FAIL $name expected $want got $got"; docker logs --tail 30 "$NAME" || true; exit 1; }
  echo "PASS $name ($got)"
}
put_state() { # $1 = local file; install as root-owned 0644 at $STATE
  docker cp "$1" "$NAME:$STATE.tmp"
  docker exec "$NAME" bash -lc "chmod 644 '$STATE.tmp' && mv '$STATE.tmp' '$STATE'"
}
mkstate() { # $1 out, $2 variant
  python3 - "$1" "$2" "$SID" "$ROLE" <<'PY'
import json, sys, time
out, variant, sid, role = sys.argv[1:]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
good = {"generated_at": now,
        "active_sessions": [{"sid": sid, "role": role, "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                             "tenant_id": "11111111-1111-1111-1111-111111111111", "expires_at": "2099-01-01T00:00:00Z", "jti": None}],
        "revoked_sids": [], "denied_jtis": []}
txt = None
if variant == "good":
    pass
elif variant == "malformed":
    txt = '{"generated_at": "' + now + '", "active_sessions": [ {"sid": "' + sid + '"'
elif variant == "trailing":
    txt = json.dumps(good) + ' {"x":1}'
elif variant == "unknown_key":
    good["allow_everyone"] = True
elif variant == "substring_confusion":
    # sid and role both appear, but never together in one active entry.
    good["active_sessions"] = [{"sid": sid, "role": "app_s_ffffffffffffffffffffffffffffffff"},
                               {"sid": "ffffffff-ffff-ffff-ffff-ffffffffffff", "role": role}]
elif variant == "escaped":
    txt = json.dumps(good).replace(sid, sid[:-1] + "\\u0031")
elif variant == "missing_generated_at":
    del good["generated_at"]
elif variant == "revoked_listed":
    good["revoked_sids"] = [sid]
elif variant == "big":
    good["revoked_sids"] = ["%08x-0000-0000-0000-000000000000" % i for i in range(400)]
elif variant == "wrong_type":
    good["revoked_sids"] = {"sid": sid}
else:
    raise SystemExit("unknown variant " + variant)
open(out, "w").write(txt if txt is not None else json.dumps(good))
PY
}

# Point the validator at the sync dir state file.
mkstate "$WORK/s.json" good; put_state "$WORK/s.json"
gucset pg_appsec.oauth_session_state_file "$STATE"
docker exec "$NAME" bash -lc ": > '$JTI'; chown postgres:postgres '$JTI'"

echo "== A. strict parser"
expect parser_good ok
for v in malformed trailing unknown_key substring_confusion escaped missing_generated_at revoked_listed wrong_type; do
  mkstate "$WORK/s.json" "$v"; put_state "$WORK/s.json"; expect "parser_$v" fail
done
mkstate "$WORK/s.json" big; put_state "$WORK/s.json"
SZ=$(stat -c %s "$WORK/s.json"); echo "big state bytes=$SZ"
gucset pg_appsec.oauth_session_state_max_bytes 4096
expect parser_oversized fail
gucreset pg_appsec.oauth_session_state_max_bytes
expect parser_same_file_under_default_cap ok

echo "== B. jti prune + cap"
mkstate "$WORK/s.json" good; put_state "$WORK/s.json"
NOW=$(date +%s)
printf 'expired-jti-1 %s\nexpired-jti-2 %s\nlive-jti-1 %s\n' $((NOW - 4000)) $((NOW - 3000)) $((NOW + 4000)) > "$WORK/jti.txt"
docker cp "$WORK/jti.txt" "$NAME:$JTI"; docker exec "$NAME" chown postgres:postgres "$JTI"
REPLAY=$TD/token_p${NEXT}.txt
expect jti_login_prunes ok
docker exec "$NAME" cat "$JTI" > "$WORK/jti_after.txt"; cat "$WORK/jti_after.txt"
if grep -q '^expired-jti' "$WORK/jti_after.txt"; then echo "FAIL expired jti not pruned"; exit 1; fi
grep -q '^live-jti-1 ' "$WORK/jti_after.txt" || { echo "FAIL live jti dropped"; exit 1; }
grep -Eq '^jti-p[0-9]+-[0-9a-f]+ [0-9]+$' "$WORK/jti_after.txt" || { echo "FAIL new jti not recorded with exp"; exit 1; }
echo "PASS jti_pruned_by_exp"
if try_login "$REPLAY"; then echo "FAIL jti replay accepted"; exit 1; fi
echo "PASS jti_replay_after_prune (fail)"
printf 'live-a %s\nlive-b %s\nlive-c %s\n' $((NOW + 4000)) $((NOW + 4000)) $((NOW + 4000)) > "$WORK/jti.txt"
docker cp "$WORK/jti.txt" "$NAME:$JTI"; docker exec "$NAME" chown postgres:postgres "$JTI"
gucset pg_appsec.oauth_jti_max_entries 3
expect jti_cap_exceeded fail
gucreset pg_appsec.oauth_jti_max_entries
expect jti_cap_restored ok
printf 'garbage-line-without-exp\n%0600d\n' 0 > "$WORK/jti.txt"
docker cp "$WORK/jti.txt" "$NAME:$JTI"; docker exec "$NAME" chown postgres:postgres "$JTI"
expect jti_overlong_line fail
docker exec "$NAME" bash -lc ": > '$JTI'"

echo "== C. live oauth-state-sync worker"
for f in sql/001_roles.sql sql/002_schema.sql sql/003_policies.sql sql/004_identity_sessions_acl.sql \
         sql/005_schema_security.sql sql/006_custom_rls.sql sql/007_hardening.sql \
         sql/008_secdefiner_audit_and_pool.sql sql/009_close_remaining_risks.sql sql/010_least_privilege_owners.sql; do
  psqlc < "$ROOT/$f" >/dev/null
done
psqlc <<SQL >/dev/null
GRANT appsec_app_base TO $ROLE;
INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES
 ('11111111-1111-1111-1111-111111111111','t1','T1','active') ON CONFLICT DO NOTHING;
INSERT INTO appsec.users(user_id,email,status,tenant_id) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a@t1','active','11111111-1111-1111-1111-111111111111') ON CONFLICT DO NOTHING;
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method) VALUES
 ('$SID','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',now()+interval '1 day','password')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL, expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role) VALUES
 ('$SID','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','$ROLE')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;
SQL
docker cp "$BIN" "$NAME:/usr/local/bin/oauth-state-sync"
docker exec "$NAME" bash -lc "rm -f '$STATE'"
DBURL='postgres:///postgres?host=/var/run/postgresql&user=postgres'
start_worker() {
  docker exec -d -u postgres "$NAME" bash -c "echo \$\$ > '$DATADIR/sync/worker.pid'; exec /usr/local/bin/oauth-state-sync --database-url '$DBURL' --session-state-file '$STATE' --poll-secs 1 >> '$DATADIR/sync/worker.log' 2>&1"
  for i in $(seq 1 50); do docker exec "$NAME" test -s "$STATE" && return 0; sleep 0.2; done
  docker exec "$NAME" cat "$DATADIR/sync/worker.log" || true
  echo "FAIL worker did not write state"; exit 1
}
start_worker
docker exec "$NAME" cat "$STATE"; echo
expect sync_active_session ok

psqlc -c "UPDATE appsec.sessions SET revoked_at = clock_timestamp() WHERE session_id = '$SID'"
T0=$(date +%s.%N); DENIED=""
for i in $(seq 1 25); do
  next_token
  if ! try_login "$TOK"; then DENIED=$(python3 -c "import time;print(round(time.time()-$T0,2))"); break; fi
  sleep 0.2
done
[[ -n $DENIED ]] || { echo "FAIL revoked session still accepted after 5s"; exit 1; }
python3 -c "import sys; sys.exit(0 if $DENIED <= 5 else 1)" || { echo "FAIL revocation took ${DENIED}s"; exit 1; }
echo "PASS sync_revoke_denied_within_5s (${DENIED}s)"
expect sync_revoke_stays_denied fail

psqlc -c "UPDATE appsec.sessions SET revoked_at = NULL WHERE session_id = '$SID'"
OK=""
for i in $(seq 1 25); do next_token; if try_login "$TOK"; then OK=1; break; fi; sleep 0.2; done
[[ -n $OK ]] || { echo "FAIL un-revoked session not restored"; exit 1; }
echo "PASS sync_unrevoke_restored"

gucset pg_appsec.oauth_session_state_max_age_secs 3
expect sync_worker_alive_short_max_age ok
docker exec "$NAME" bash -lc "kill \$(cat '$DATADIR/sync/worker.pid')"
sleep 5
expect sync_worker_killed_fails_closed fail
start_worker
sleep 1
expect sync_worker_restarted_recovers ok
gucreset pg_appsec.oauth_session_state_max_age_secs

echo "== D. signed audit checkpoints"
python3 - "$WORK" <<'PY'
import sys, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
seed = secrets.token_bytes(32)
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
open(sys.argv[1] + "/audit_seed.hex", "w").write(seed.hex())
open(sys.argv[1] + "/audit_pub.hex", "w").write(pub.hex())
PY
docker cp "$WORK/audit_seed.hex" "$NAME:$DATADIR/sync/audit_seed.hex"
docker cp "$WORK/audit_pub.hex" "$NAME:/tmp/audit_pub.hex"
docker exec "$NAME" bash -lc "chown postgres:postgres '$DATADIR/sync/audit_seed.hex' && chmod 600 '$DATADIR/sync/audit_seed.hex' && chmod 644 /tmp/audit_pub.hex"
psqlc -c "SELECT appsec.audit_event('ci.e2e', 'checkpoint', '{\"n\":1}'::jsonb)" >/dev/null
CP="$DATADIR/sync/checkpoints.log"
cpw() { docker exec -u postgres "$NAME" /usr/local/bin/oauth-state-sync --database-url "$DBURL" --audit-checkpoint-file "$CP" "$@"; }
cpw --audit-signing-key-file "$DATADIR/sync/audit_seed.hex" --checkpoint-once --checkpoint-stdout
psqlc -c "SELECT appsec.audit_event('ci.e2e', 'checkpoint', '{\"n\":2}'::jsonb)" >/dev/null
cpw --verify-checkpoint-with /tmp/audit_pub.hex || { echo "FAIL checkpoint verify on clean chain"; exit 1; }
echo "PASS checkpoint_verify_ok"
# Signature tamper: edit event_id in the last line.
docker exec "$NAME" bash -lc "cp '$CP' '$CP.bak' && sed -i -E 's/\"event_id\":([0-9]+)/\"event_id\":1\\1/' '$CP'"
if cpw --verify-checkpoint-with /tmp/audit_pub.hex; then echo "FAIL tampered checkpoint accepted"; exit 1; fi
echo "PASS checkpoint_signature_tamper_detected"
docker exec "$NAME" bash -lc "mv '$CP.bak' '$CP'"
# Wrong key.
python3 -c "print('11'*32)" > "$WORK/other.hex"; docker cp "$WORK/other.hex" "$NAME:/tmp/other_pub.hex"; docker exec "$NAME" chmod 644 /tmp/other_pub.hex
if cpw --verify-checkpoint-with /tmp/other_pub.hex; then echo "FAIL checkpoint accepted under wrong key"; exit 1; fi
echo "PASS checkpoint_wrong_key_rejected"
# Superuser rewrites the whole chain consistently: internal verify passes, anchor catches it.
psqlc <<'SQL' >/dev/null
ALTER TABLE appsec.security_audit_chain DISABLE TRIGGER USER;
DO $$
DECLARE r record; prev bytea := decode(repeat('00', 32), 'hex'); h bytea;
BEGIN
  FOR r IN SELECT * FROM appsec.security_audit_chain ORDER BY event_id LOOP
    h := appsec.digest(convert_to(coalesce(r.occurred_at::text,'') || '|' || coalesce(r.actor_user_id::text,'') || '|' ||
         coalesce(r.actor_role::text,'') || '|' || coalesce(r.event_type,'') || '|' ||
         coalesce(CASE WHEN r.event_type = 'ci.e2e' THEN 'forged' ELSE r.resource END,'') || '|' ||
         coalesce(r.detail::text,'{}') || '|' || encode(prev, 'hex'), 'UTF8'), 'sha256');
    UPDATE appsec.security_audit_chain SET prev_hash = prev, event_hash = h,
      resource = CASE WHEN r.event_type = 'ci.e2e' THEN 'forged' ELSE r.resource END
    WHERE event_id = r.event_id;
    prev := h;
  END LOOP;
END $$;
ALTER TABLE appsec.security_audit_chain ENABLE TRIGGER USER;
SQL
INNER=$(psqlc -c "SELECT ok FROM appsec.verify_security_audit_chain()")
echo "internal chain verify after consistent rewrite: $INNER"
[[ $INNER == t ]] || { echo "FAIL rewrite was not self-consistent (test bug)"; exit 1; }
if cpw --verify-checkpoint-with /tmp/audit_pub.hex; then echo "FAIL checkpoint missed superuser rewrite"; exit 1; fi
echo "PASS checkpoint_detects_superuser_rewrite"
echo oauth_sync_e2e_ok
