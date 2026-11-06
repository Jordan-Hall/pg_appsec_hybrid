from pathlib import Path

root = Path(__file__).resolve().parents[1]
files = [
    "001_roles.sql",
    "002_schema.sql",
    "003_policies.sql",
    "004_identity_sessions_acl.sql",
    "005_schema_security.sql",
]
parts = []
for name in files:
    source = (root / "sql" / name).read_text()
    source = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("\\set "))
    parts.append(f"-- BEGIN {name}\n{source}\n-- END {name}\n")
parts.append("""-- Restrict the Rust-exposed password helpers to application principals.
REVOKE ALL ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() TO appsec_app_base, appsec_operator_base;
""")
(root / "sql" / "install.sql").write_text("\n".join(parts))
