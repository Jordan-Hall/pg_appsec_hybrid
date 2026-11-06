/*
 * pg_appsec_oauth — PostgreSQL 18 OAuth validator for pg_appsec_hybrid.
 *
 * Verifies internal access JWTs (RS256 / ES256 / EdDSA). Fail-closed.
 * Never logs raw tokens. Configuration via custom GUCs (see README).
 *
 * SECURITY: Independent cryptographic review is still required before
 * production use.
 */
#include "postgres.h"
#include "fmgr.h"
#ifdef USE_OAUTH_ABI_HEADER
#include "oauth_abi.h"
#else
#include "libpq/oauth.h"
#endif
#include "miscadmin.h"
#include "utils/guc.h"
#include "utils/memutils.h"

#include <ctype.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <time.h>

PG_MODULE_MAGIC;

extern PGDLLEXPORT const OAuthValidatorCallbacks *_PG_oauth_validator_module_init(void);

/* GUC-backed configuration */
static char *g_issuer = NULL;
static char *g_audience = NULL;
static char *g_jwks_path = NULL;
static char *g_pubkey_path = NULL;
static char *g_required_scope = NULL;
static int	g_clock_skew = 60;
static int	g_max_token_bytes = 8192;

#define MAX_CLAIM 512

typedef struct JwtParts
{
	char	   *hdr_b64;
	char	   *pay_b64;
	char	   *sig_b64;
	char	   *signing_input;	/* hdr.pay */
	unsigned char *hdr_json;
	unsigned char *pay_json;
	size_t		hdr_len;
	size_t		pay_len;
	unsigned char *sig;
	size_t		sig_len;
} JwtParts;

static void
fail_clear(ValidatorModuleResult *result)
{
	result->authorized = false;
	result->authn_id = NULL;
}

static int
b64url_decode(const char *in, unsigned char **out, size_t *out_len)
{
	size_t		len = strlen(in);
	size_t		pad = (4 - (len % 4)) % 4;
	char	   *tmp;
	BIO		   *b64,
			   *mem;
	int			n;
	unsigned char *buf;

	tmp = palloc(len + pad + 1);
	for (size_t i = 0; i < len; i++)
	{
		char		c = in[i];

		if (c == '-')
			c = '+';
		else if (c == '_')
			c = '/';
		tmp[i] = c;
	}
	for (size_t i = 0; i < pad; i++)
		tmp[len + i] = '=';
	tmp[len + pad] = '\0';

	buf = palloc(len + pad);
	mem = BIO_new_mem_buf(tmp, (int) (len + pad));
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	mem = BIO_push(b64, mem);
	n = BIO_read(mem, buf, (int) (len + pad));
	BIO_free_all(mem);
	pfree(tmp);
	if (n <= 0)
	{
		pfree(buf);
		return -1;
	}
	*out = buf;
	*out_len = (size_t) n;
	return 0;
}

static bool
json_get_string(const char *json, size_t json_len, const char *key, char *dest, size_t dest_sz)
{
	/*
	 * Minimal string claim extractor: "key"\s*:\s*"value". Not a full JSON
	 * parser — sufficient for constrained JWT claim sets we issue.
	 */
	char		needle[128];
	const char *p,
			   *end = json + json_len;
	size_t		klen;

	snprintf(needle, sizeof(needle), "\"%s\"", key);
	klen = strlen(needle);
	p = json;
	while (p + klen < end)
	{
		if (memcmp(p, needle, klen) == 0)
		{
			p += klen;
			while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
				p++;
			if (p >= end || *p != ':')
				return false;
			p++;
			while (p < end && (*p == ' ' || *p == '\t'))
				p++;
			if (p >= end || *p != '"')
				return false;
			p++;
			{
				size_t		i = 0;

				while (p < end && *p != '"' && i + 1 < dest_sz)
				{
					if (*p == '\\' && p + 1 < end)
					{
						p++;
						dest[i++] = *p++;
					}
					else
						dest[i++] = *p++;
				}
				if (p >= end || *p != '"')
					return false;
				dest[i] = '\0';
				return true;
			}
		}
		p++;
	}
	return false;
}

static bool
json_get_int64(const char *json, size_t json_len, const char *key, int64_t *out)
{
	char		needle[128];
	const char *p,
			   *end = json + json_len;
	size_t		klen;

	snprintf(needle, sizeof(needle), "\"%s\"", key);
	klen = strlen(needle);
	p = json;
	while (p + klen < end)
	{
		if (memcmp(p, needle, klen) == 0)
		{
			p += klen;
			while (p < end && isspace((unsigned char) *p))
				p++;
			if (p >= end || *p != ':')
				return false;
			p++;
			while (p < end && isspace((unsigned char) *p))
				p++;
			{
				char	   *ep = NULL;
				long long	v = strtoll(p, &ep, 10);

				if (ep == p)
					return false;
				*out = (int64_t) v;
				return true;
			}
		}
		p++;
	}
	return false;
}

static bool
scope_contains(const char *scope, const char *need)
{
	const char *p = scope;
	size_t		nlen = strlen(need);

	if (!scope || !need || nlen == 0)
		return false;
	while (*p)
	{
		while (*p == ' ')
			p++;
		if (strncmp(p, need, nlen) == 0 && (p[nlen] == '\0' || p[nlen] == ' '))
			return true;
		while (*p && *p != ' ')
			p++;
	}
	return false;
}

static bool
parse_jwt(const char *token, JwtParts *jp)
{
	const char *d1,
			   *d2;
	size_t		tlen = strlen(token);

	memset(jp, 0, sizeof(*jp));
	if (tlen == 0 || tlen > (size_t) g_max_token_bytes)
		return false;
	d1 = strchr(token, '.');
	if (!d1)
		return false;
	d2 = strchr(d1 + 1, '.');
	if (!d2 || strchr(d2 + 1, '.'))
		return false;

	jp->hdr_b64 = pnstrdup(token, d1 - token);
	jp->pay_b64 = pnstrdup(d1 + 1, d2 - (d1 + 1));
	jp->sig_b64 = pstrdup(d2 + 1);
	jp->signing_input = pnstrdup(token, d2 - token);

	if (b64url_decode(jp->hdr_b64, &jp->hdr_json, &jp->hdr_len) != 0)
		return false;
	if (b64url_decode(jp->pay_b64, &jp->pay_json, &jp->pay_len) != 0)
		return false;
	if (b64url_decode(jp->sig_b64, &jp->sig, &jp->sig_len) != 0)
		return false;
	return true;
}

static EVP_PKEY *
load_pubkey_pem(const char *path)
{
	FILE	   *f;
	EVP_PKEY   *pkey;

	if (!path || path[0] == '\0')
		return NULL;
	f = fopen(path, "r");
	if (!f)
		return NULL;
	pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	fclose(f);
	return pkey;
}

static EVP_PKEY *
load_pubkey_from_jwks(const char *path, const char *alg)
{
	/*
	 * Minimal JWKS: prefer a PEM sibling when present. Full JWK RSA/OKP
	 * import is complex; we also accept a top-level {"pem":"-----BEGIN..."}.
	 */
	FILE	   *f;
	char	   *buf;
	long		sz;
	char		pem[8192];
	BIO		   *bio;
	EVP_PKEY   *pkey = NULL;

	(void) alg;
	if (!path || path[0] == '\0')
		return NULL;
	f = fopen(path, "r");
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return NULL;
	}
	sz = ftell(f);
	if (sz <= 0 || sz > 1024 * 1024)
	{
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = palloc((size_t) sz + 1);
	if (fread(buf, 1, (size_t) sz, f) != (size_t) sz)
	{
		fclose(f);
		pfree(buf);
		return NULL;
	}
	fclose(f);
	buf[sz] = '\0';

	if (json_get_string(buf, (size_t) sz, "pem", pem, sizeof(pem)))
	{
		bio = BIO_new_mem_buf(pem, -1);
		if (bio)
		{
			pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
	}
	pfree(buf);
	return pkey;
}

static bool
verify_sig(EVP_PKEY *pkey, const char *alg, const char *signing_input,
		   const unsigned char *sig, size_t sig_len)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md = NULL;
	int			rc;
	size_t		in_len = strlen(signing_input);

	if (!pkey || !alg)
		return false;

	/* Reject alg=none and HMAC families (no public-key confusion). */
	if (strcmp(alg, "none") == 0 || strncmp(alg, "HS", 2) == 0)
		return false;

	if (strcmp(alg, "RS256") == 0)
		md = EVP_sha256();
	else if (strcmp(alg, "ES256") == 0)
		md = EVP_sha256();
	else if (strcmp(alg, "EdDSA") == 0)
		md = NULL;				/* pure Ed25519 */
	else
		return false;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return false;

	if (strcmp(alg, "EdDSA") == 0)
	{
		if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1)
		{
			EVP_MD_CTX_free(ctx);
			return false;
		}
		rc = EVP_DigestVerify(ctx, sig, sig_len,
							  (const unsigned char *) signing_input, in_len);
	}
	else if (strcmp(alg, "ES256") == 0)
	{
		/* JWT ES256 signature is raw r||s; OpenSSL wants DER. Convert. */
		ECDSA_SIG *ecsig;
		BIGNUM	   *r,
				   *s;
		unsigned char *der = NULL;
		int			der_len;

		if (sig_len != 64)
		{
			EVP_MD_CTX_free(ctx);
			return false;
		}
		ecsig = ECDSA_SIG_new();
		r = BN_bin2bn(sig, 32, NULL);
		s = BN_bin2bn(sig + 32, 32, NULL);
		if (!ecsig || !r || !s || ECDSA_SIG_set0(ecsig, r, s) != 1)
		{
			BN_free(r);
			BN_free(s);
			ECDSA_SIG_free(ecsig);
			EVP_MD_CTX_free(ctx);
			return false;
		}
		der_len = i2d_ECDSA_SIG(ecsig, &der);
		ECDSA_SIG_free(ecsig);
		if (der_len <= 0)
		{
			EVP_MD_CTX_free(ctx);
			return false;
		}
		if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1)
		{
			OPENSSL_free(der);
			EVP_MD_CTX_free(ctx);
			return false;
		}
		rc = EVP_DigestVerify(ctx, der, (size_t) der_len,
							  (const unsigned char *) signing_input, in_len);
		OPENSSL_free(der);
	}
	else
	{
		if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1)
		{
			EVP_MD_CTX_free(ctx);
			return false;
		}
		rc = EVP_DigestVerify(ctx, sig, sig_len,
							  (const unsigned char *) signing_input, in_len);
	}

	EVP_MD_CTX_free(ctx);
	return rc == 1;
}

static bool
expected_role_from_sid(const char *sid, char *out, size_t out_sz)
{
	/* sid UUID → app_s_<32 hex lowercase without hyphens> */
	char		hex[33];
	size_t		hi = 0;

	if (!sid)
		return false;
	for (const char *p = sid; *p; p++)
	{
		if (*p == '-')
			continue;
		if (!isxdigit((unsigned char) *p) || hi >= 32)
			return false;
		hex[hi++] = (char) tolower((unsigned char) *p);
	}
	hex[hi] = '\0';
	if (hi != 32)
		return false;
	snprintf(out, out_sz, "app_s_%s", hex);
	return true;
}

static bool
pg_appsec_validate(const ValidatorModuleState *state,
				   const char *token,
				   const char *role,
				   ValidatorModuleResult *result)
{
	JwtParts	jp;
	char		alg[32] = {0};
	char		iss[MAX_CLAIM] = {0};
	char		aud[MAX_CLAIM] = {0};
	char		sub[MAX_CLAIM] = {0};
	char		sid[MAX_CLAIM] = {0};
	char		pref[MAX_CLAIM] = {0};
	char		token_use[64] = {0};
	char		scope[MAX_CLAIM] = {0};
	char		expect_role[80] = {0};
	int64_t		exp = 0,
				nbf = 0,
				iat = 0;
	time_t		now;
	EVP_PKEY   *pkey = NULL;

	(void) state;
	fail_clear(result);

	if (!token || !role || role[0] == '\0')
		return true;
	if (!g_issuer || !g_audience || g_issuer[0] == '\0' || g_audience[0] == '\0')
		return true;			/* misconfigured → deny */

	if (!parse_jwt(token, &jp))
		return true;

	if (!json_get_string((const char *) jp.hdr_json, jp.hdr_len, "alg", alg, sizeof(alg)))
		return true;
	if (strcmp(alg, "none") == 0 || strncmp(alg, "HS", 2) == 0)
		return true;
	if (strcmp(alg, "RS256") != 0 && strcmp(alg, "ES256") != 0 && strcmp(alg, "EdDSA") != 0)
		return true;

	pkey = load_pubkey_pem(g_pubkey_path);
	if (!pkey)
		pkey = load_pubkey_from_jwks(g_jwks_path, alg);
	if (!pkey)
		return true;

	if (!verify_sig(pkey, alg, jp.signing_input, jp.sig, jp.sig_len))
	{
		EVP_PKEY_free(pkey);
		return true;
	}
	EVP_PKEY_free(pkey);

	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "iss", iss, sizeof(iss))
		|| strcmp(iss, g_issuer) != 0)
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "aud", aud, sizeof(aud))
		|| strcmp(aud, g_audience) != 0)
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "sub", sub, sizeof(sub)))
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "sid", sid, sizeof(sid)))
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "preferred_username", pref, sizeof(pref)))
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "token_use", token_use, sizeof(token_use))
		|| strcmp(token_use, "access") != 0)
		return true;
	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "scope", scope, sizeof(scope)))
		return true;
	if (!scope_contains(scope, g_required_scope && g_required_scope[0] ? g_required_scope : "pg_appsec"))
		return true;

	if (!json_get_int64((const char *) jp.pay_json, jp.pay_len, "exp", &exp))
		return true;
	json_get_int64((const char *) jp.pay_json, jp.pay_len, "nbf", &nbf);
	json_get_int64((const char *) jp.pay_json, jp.pay_len, "iat", &iat);
	now = time(NULL);
	if (exp + g_clock_skew < (int64_t) now)
		return true;
	if (nbf && nbf > (int64_t) now + g_clock_skew)
		return true;
	if (iat && iat > (int64_t) now + g_clock_skew)
		return true;

	if (!expected_role_from_sid(sid, expect_role, sizeof(expect_role)))
		return true;
	if (strcmp(pref, expect_role) != 0)
		return true;
	if (strcmp(role, expect_role) != 0 || strcmp(role, pref) != 0)
		return true;

	/*
	 * Session revocation is enforced by appsec.uid() / RLS on every
	 * statement after connect (session_principals + sessions). The
	 * validator intentionally does not open a DB connection during
	 * authentication.
	 */
	result->authorized = true;
	result->authn_id = pstrdup(pref);
	return true;
}

static const OAuthValidatorCallbacks pg_appsec_callbacks = {
	.magic = PG_OAUTH_VALIDATOR_MAGIC,
	.startup_cb = NULL,
	.shutdown_cb = NULL,
	.validate_cb = pg_appsec_validate
};

void
_PG_init(void)
{
	DefineCustomStringVariable("pg_appsec.oauth_issuer",
							   "Expected JWT iss claim",
							   NULL,
							   &g_issuer,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_audience",
							   "Expected JWT aud claim",
							   NULL,
							   &g_audience,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_jwks_file",
							   "Path to JWKS JSON (optional; may include pem field)",
							   NULL,
							   &g_jwks_path,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_pubkey_file",
							   "Path to PEM SubjectPublicKeyInfo for JWT verify",
							   NULL,
							   &g_pubkey_path,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_required_scope",
							   "Required OAuth scope token claim",
							   NULL,
							   &g_required_scope,
							   "pg_appsec",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_appsec.oauth_clock_skew_secs",
							"Allowed JWT clock skew in seconds",
							NULL,
							&g_clock_skew,
							60,
							0, 600,
							PGC_SIGHUP,
							0, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_appsec.oauth_max_token_bytes",
							"Maximum accepted JWT size",
							NULL,
							&g_max_token_bytes,
							8192,
							256, 65536,
							PGC_SIGHUP,
							0, NULL, NULL, NULL);
}

__attribute__((visibility("default"))) PGDLLEXPORT const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &pg_appsec_callbacks;
}
