#!/usr/bin/env python3
from pathlib import Path
import base64, json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

td = Path(__file__).resolve().parent / "testdata"
td.mkdir(exist_ok=True)
priv_path = td / "ed25519_private.pem"
pub_path = td / "ed25519_public.pem"
if not priv_path.exists():
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub_path.write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
else:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
pub_pem = pub_path.read_text()
(td / "jwks.json").write_text(json.dumps({"pem": pub_pem}))

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def mint(**claims):
    hdr = {"alg": "EdDSA", "typ": "JWT"}
    now = int(time.time())
    body = {
        "iss": "https://pg-appsec.test",
        "aud": "pg_appsec",
        "token_use": "access",
        "scope": "openid pg_appsec",
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": "test-jti",
        **claims,
    }
    h = b64url(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url(json.dumps(body, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    return f"{h}.{p}.{b64url(priv.sign(msg))}"

sid = "a1111111-a111-a111-a111-a11111111111"
role = "app_s_" + sid.replace("-", "")
(td / "token_valid.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role))
(td / "token_expired.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, exp=int(time.time()) - 100, iat=int(time.time()) - 200, nbf=int(time.time()) - 200))
(td / "token_wrong_aud.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, aud="other"))
(td / "token_wrong_iss.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, iss="https://evil.test"))
(td / "token_wrong_role.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username="app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
h = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
p = b64url(json.dumps({"iss": "https://pg-appsec.test", "aud": "pg_appsec", "sub": "x", "sid": sid, "preferred_username": role, "token_use": "access", "scope": "pg_appsec", "exp": int(time.time()) + 900}, separators=(",", ":")).encode())
(td / "token_alg_none.txt").write_text(f"{h}.{p}.")
tok = (td / "token_valid.txt").read_text().strip()
(td / "token_badsig.txt").write_text(tok.rsplit(".", 1)[0] + "." + b64url(b"\x00" * 64))
state = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "active_sessions": [{"sid": sid, "role": role, "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "tenant_id": "11111111-1111-1111-1111-111111111111", "expires_at": "2099-01-01", "jti": "test-jti"}],
    "revoked_sids": [],
    "denied_jtis": [],
}
(td / "session_state.json").write_text(json.dumps(state, separators=(",", ":")))
(td / "session_state_revoked.json").write_text(json.dumps({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "active_sessions": [], "revoked_sids": [sid], "denied_jtis": ["denied-jti"]}, separators=(",", ":")))
(td / "jti_denylist.txt").write_text("denied-jti\n")
# JWKS with kid for rotation
pub_pem = pub_path.read_text()
(td / "jwks_kid.json").write_text(json.dumps({"keys": [{"kid": "k1", "pem": pub_pem}]}, separators=(",", ":")))
# token with kid header
def mint_kid(**claims):
    hdr = {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
    now = int(time.time())
    body = {
        "iss": "https://pg-appsec.test",
        "aud": "pg_appsec",
        "token_use": "access",
        "scope": "openid pg_appsec",
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": "test-jti-kid",
        **claims,
    }
    h = b64url(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url(json.dumps(body, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    return f"{h}.{p}.{b64url(priv.sign(msg))}"
(td / "token_kid.json").write_text("")  # placeholder
(td / "token_valid_kid.txt").write_text(mint_kid(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role))
(td / "token_revoked_sid.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, jti="jti-rev-check"))
(td / "token_stale_probe.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, jti="jti-stale-probe"))
print("minted tokens for", role)

# Fresh single-use probe tokens for parser / jti / sync-worker E2E phases.
import secrets as _secrets
_run = _secrets.token_hex(4)
for _n in range(1, 161):
    (td / f"token_p{_n}.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, tenant_id="11111111-1111-1111-1111-111111111111", jti=f"jti-p{_n}-{_run}"))
for _n in range(1, 4):
    (td / f"token_nt{_n}.txt").write_text(mint(sub="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sid=sid, preferred_username=role, jti=f"jti-nt{_n}-{_run}"))
