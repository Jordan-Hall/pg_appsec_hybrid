-- Run as a database administrator. Keep this login private to the Rust auth service.
CREATE ROLE appsec_auth_svc LOGIN PASSWORD 'REPLACE_WITH_RANDOM_SECRET'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT appsec_provisioner TO appsec_auth_svc;
GRANT CONNECT ON DATABASE appdb TO appsec_auth_svc;
-- The login itself does not inherit CREATEROLE. The Rust service executes
-- SET LOCAL ROLE appsec_provisioner within each narrowly scoped transaction.
