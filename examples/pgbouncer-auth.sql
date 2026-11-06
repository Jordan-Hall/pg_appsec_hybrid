-- Run as a database administrator. Use a long random secret and store its
-- SCRAM verifier in PgBouncer's protected userlist.txt (mode 0600).
CREATE ROLE pgbouncer_auth LOGIN PASSWORD 'REPLACE_WITH_RANDOM_SECRET'
  NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
GRANT appsec_pool_auth TO pgbouncer_auth;
-- appsec_pool_auth has USAGE on appsec and EXECUTE only on pgbouncer_lookup().
