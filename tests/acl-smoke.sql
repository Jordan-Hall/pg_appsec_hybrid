\set ON_ERROR_STOP on
-- Run only in a disposable PostgreSQL 18 test database after migrations 001-004.
-- This file is a test fixture template; it is not a substitute for the adversarial suite.
BEGIN;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='appsec_test_user') THEN
    CREATE ROLE appsec_test_user LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END $$;
ROLLBACK;
