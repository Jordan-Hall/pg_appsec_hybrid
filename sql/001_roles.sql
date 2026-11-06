\set ON_ERROR_STOP on

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_owner') THEN
    CREATE ROLE appsec_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_provisioner') THEN
    CREATE ROLE appsec_provisioner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_app_base') THEN
    CREATE ROLE appsec_app_base NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_operator_base') THEN
    CREATE ROLE appsec_operator_base NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_pool_auth') THEN
    CREATE ROLE appsec_pool_auth NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS appsec AUTHORIZATION appsec_owner;
REVOKE ALL ON SCHEMA appsec FROM PUBLIC;
GRANT USAGE ON SCHEMA appsec TO appsec_app_base, appsec_operator_base, appsec_pool_auth;
GRANT USAGE, CREATE ON SCHEMA appsec TO appsec_owner;
GRANT appsec_app_base TO appsec_operator_base;

ALTER DEFAULT PRIVILEGES FOR ROLE appsec_owner IN SCHEMA appsec REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE appsec_owner IN SCHEMA appsec REVOKE ALL ON TABLES FROM PUBLIC;

-- This is a non-login control-plane role. Grant it only to a dedicated
-- provisioning service identity, never to the application runtime role.
ALTER ROLE appsec_provisioner CREATEROLE;
GRANT appsec_app_base TO appsec_provisioner WITH ADMIN OPTION;
