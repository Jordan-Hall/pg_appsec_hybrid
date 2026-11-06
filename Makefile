PG_CONFIG ?= pg_config
PGHOST ?= localhost
PGPORT ?= 5432
PGUSER ?= postgres
PGDATABASE ?= appsec_test
PSQL ?= psql

.PHONY: test rust-test typecheck sql-install sql-test oauth-build clean pgrx-init extension-build extension-install extension-test build-install-sql

test: rust-test typecheck

pgrx-init:
	cargo pgrx init --pg18 $(PG_CONFIG)

extension-build:
	cargo pgrx package --pg-config $(PG_CONFIG)

extension-install:
	cargo pgrx install --pg-config $(PG_CONFIG)

extension-test:
	cargo pgrx test pg18

rust-test:
	cargo test -p pg-appsec-auth --all-targets

typecheck:
	tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext sdk/typescript/index.ts

build-install-sql:
	python3 tools/build_install_sql.py

sql-install:
	$(PSQL) -v ON_ERROR_STOP=1 -f sql/001_roles.sql
	$(PSQL) -v ON_ERROR_STOP=1 -f sql/002_schema.sql
	$(PSQL) -v ON_ERROR_STOP=1 -f sql/003_policies.sql
	$(PSQL) -v ON_ERROR_STOP=1 -f sql/004_identity_sessions_acl.sql
	$(PSQL) -v ON_ERROR_STOP=1 -f sql/005_schema_security.sql

sql-test:
	$(PSQL) -v ON_ERROR_STOP=1 -f tests/pg_appsec_adversarial.sql
oauth-build:
	$(MAKE) -C oauth-validator PG_CONFIG=$(PG_CONFIG)

clean:
	$(MAKE) -C oauth-validator PG_CONFIG=$(PG_CONFIG) clean
	cargo clean
