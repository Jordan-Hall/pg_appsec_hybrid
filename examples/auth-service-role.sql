-- Run as a database administrator. Keep this login private to the Rust auth service.
CREATE ROLE pg_appsec_auth LOGIN PASSWORD 'REPLACE_WITH_RANDOM_SECRET'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT appsec_provisioner TO pg_appsec_auth;
GRANT CONNECT ON DATABASE appdb TO pg_appsec_auth;
-- The login itself does not inherit CREATEROLE. The Rust service executes
-- SET LOCAL ROLE appsec_provisioner within each narrowly scoped transaction.
