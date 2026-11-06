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
print("minted tokens for", role)
