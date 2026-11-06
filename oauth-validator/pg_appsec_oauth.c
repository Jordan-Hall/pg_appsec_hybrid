/* Enable strptime/timegm on glibc */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <sys/stat.h>

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
static char *g_session_state_file = NULL;
static char *g_jti_denylist_file = NULL;
static char *g_issuer_map_file = NULL;
static int	g_session_state_max_age = 120;

#define MAX_CLAIM 512
#define JTI_SEEN_CAP 4096
static char	jti_seen[JTI_SEEN_CAP][MAX_CLAIM];
static int	jti_seen_n = 0;


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
pem_to_pkey(const char *pem)
{
	BIO		   *bio;
	EVP_PKEY   *pkey;

	bio = BIO_new_mem_buf(pem, -1);
	if (!bio)
		return NULL;
	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return pkey;
}

static EVP_PKEY *
load_pubkey_from_jwks(const char *path, const char *alg, const char *kid)
{
	/*
	 * JWKS shapes supported:
	 * 1) {"pem":"-----BEGIN..."} (legacy)
	 * 2) {"keys":[{"kid":"...","pem":"-----BEGIN..."}, ...]} for rotation
	 */
	FILE	   *f;
	char	   *buf;
	long		sz;
	char		pem[8192];
	EVP_PKEY   *pkey = NULL;
	const char *p;

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

	if (kid && kid[0] != '\0')
	{
		/* naive scan: find "kid":"<kid>" then nearest "pem" afterward in the same object */
		char		needle[MAX_CLAIM + 16];
		const char *hit;

		snprintf(needle, sizeof(needle), "\"kid\":\"%s\"", kid);
		hit = strstr(buf, needle);
		if (hit)
		{
			const char *obj_end = strchr(hit, '}');
			const char *pem_key = strstr(hit, "\"pem\"");

			if (pem_key && obj_end && pem_key < obj_end)
			{
				if (json_get_string(pem_key, (size_t) (obj_end - pem_key) + 1, "pem", pem, sizeof(pem)))
					pkey = pem_to_pkey(pem);
			}
		}
	}
	if (!pkey && json_get_string(buf, (size_t) sz, "pem", pem, sizeof(pem)))
		pkey = pem_to_pkey(pem);
	/* fallback: first keys[].pem */
	if (!pkey && (p = strstr(buf, "\"pem\"")) != NULL)
	{
		if (json_get_string(p, strlen(p), "pem", pem, sizeof(pem)))
			pkey = pem_to_pkey(pem);
	}
	pfree(buf);
	return pkey;
}

static bool
file_contains_line_or_json_value(const char *path, const char *needle)
{
	FILE	   *f;
	char		line[4096];

	if (!path || path[0] == '\0' || !needle || needle[0] == '\0')
		return false;
	f = fopen(path, "r");
	if (!f)
		return false;
	while (fgets(line, sizeof(line), f))
	{
		if (strstr(line, needle) != NULL)
		{
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

static bool
session_state_allows(const char *sid, const char *role)
{
	FILE	   *f;
	char	   *buf;
	long		sz;
	bool		ok = false;
	char		role_needle[128];
	char		sid_needle[128];
	struct stat st;
	time_t		now;
	const char *gat;
	char		tsbuf[64];
	struct tm	tm;
	time_t		generated;

	/* If no state file configured, allow (RLS still enforces post-connect). */
	if (!g_session_state_file || g_session_state_file[0] == '\0')
		return true;
	if (stat(g_session_state_file, &st) != 0)
		return false;			/* fail closed when configured but missing */
	now = time(NULL);
	if (g_session_state_max_age > 0
		&& st.st_mtime + g_session_state_max_age < now)
		return false;			/* fail closed: sync worker stale */
	f = fopen(g_session_state_file, "r");
	if (!f)
		return false;			/* fail closed when configured but missing */
	if (fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return false;
	}
	sz = ftell(f);
	if (sz <= 0 || sz > 8 * 1024 * 1024)
	{
		fclose(f);
		return false;
	}
	rewind(f);
	buf = palloc((size_t) sz + 1);
	if (fread(buf, 1, (size_t) sz, f) != (size_t) sz)
	{
		fclose(f);
		pfree(buf);
		return false;
	}
	fclose(f);
	buf[sz] = '\0';

	/* Prefer JSON generated_at when present (more reliable than mtime across mounts). */
	gat = strstr(buf, "\"generated_at\"");
	if (gat && g_session_state_max_age > 0)
	{
		const char *q1 = strchr(gat + 14, '"');
		const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;

		if (q1 && q2 && (q2 - q1 - 1) < (long) sizeof(tsbuf))
		{
			memset(tsbuf, 0, sizeof(tsbuf));
			memcpy(tsbuf, q1 + 1, (size_t) (q2 - q1 - 1));
			/* Accept RFC3339 UTC (...Z) by zeroing fractional/zone for timegm-ish parse of YYYY-MM-DDTHH:MM:SS */
			if (strlen(tsbuf) >= 19)
			{
				tsbuf[19] = '\0';
				memset(&tm, 0, sizeof(tm));
				if (strptime(tsbuf, "%Y-%m-%dT%H:%M:%S", &tm) != NULL)
				{
#if defined(__linux__)
					generated = timegm(&tm);
#else
					generated = timegm(&tm);
#endif
					if (generated > 0 && generated + g_session_state_max_age < now)
					{
						pfree(buf);
						return false;
					}
				}
			}
		}
	}

	/* Revoked list wins. */
	snprintf(sid_needle, sizeof(sid_needle), "%s", sid);
	if (strstr(buf, "\"revoked_sids\"") && strstr(buf, sid_needle))
	{
		/* crude: if sid appears inside revoked_sids array region — treat as deny if listed after key */
		const char *rev = strstr(buf, "\"revoked_sids\"");
		const char *act = strstr(buf, "\"active_sessions\"");
		const char *hit = strstr(rev, sid);

		if (hit && (!act || hit < act || (act && hit < strstr(act, "]") && rev < act)))
		{
			/* if hit is between revoked_sids and next major key */
			const char *end = strchr(rev, ']');

			if (end && hit < end)
			{
				pfree(buf);
				return false;
			}
		}
	}

	snprintf(role_needle, sizeof(role_needle), "\"%s\"", role);
	if (strstr(buf, sid) && strstr(buf, role_needle))
		ok = true;
	pfree(buf);
	return ok;
}

static bool
jti_denied(const char *jti)
{
	int			i;

	if (!jti || jti[0] == '\0')
		return true;
	if (g_jti_denylist_file && g_jti_denylist_file[0] != '\0'
		&& file_contains_line_or_json_value(g_jti_denylist_file, jti))
		return true;
	for (i = 0; i < jti_seen_n; i++)
	{
		if (strcmp(jti_seen[i], jti) == 0)
			return true;		/* replay within process lifetime */
	}
	return false;
}

static void
jti_remember(const char *jti)
{
	FILE	   *f;

	if (!jti || jti[0] == '\0')
		return;
	if (jti_seen_n < JTI_SEEN_CAP)
	{
		snprintf(jti_seen[jti_seen_n], MAX_CLAIM, "%s", jti);
		jti_seen_n++;
	}
	/*
	 * Persist across backends: append to the denylist/seen file when
	 * configured so jti replay fails on another postgres worker.
	 */
	if (g_jti_denylist_file && g_jti_denylist_file[0] != '\0')
	{
		f = fopen(g_jti_denylist_file, "a");
		if (f)
		{
			fprintf(f, "%s\n", jti);
			fclose(f);
		}
	}
}

static bool
issuer_allowed_for_tenant(const char *iss, const char *tenant_id)
{
	/* Optional map file: JSON {"https://issuer": ["tenant-uuid", ...]} or flat allowlist of issuers. */
	if (!g_issuer_map_file || g_issuer_map_file[0] == '\0')
		return true;			/* rely on global g_issuer pin */
	if (!file_contains_line_or_json_value(g_issuer_map_file, iss))
		return false;
	if (tenant_id && tenant_id[0] != '\0'
		&& !file_contains_line_or_json_value(g_issuer_map_file, tenant_id))
	{
		/* If file has tenant lists, require tenant mention; if only issuers, tenant check soft-pass when tenant absent from file entirely. */
		if (file_contains_line_or_json_value(g_issuer_map_file, "tenant"))
			return false;
	}
	return true;
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
	char		kid[MAX_CLAIM] = {0};
	char		jti[MAX_CLAIM] = {0};
	char		tenant[MAX_CLAIM] = {0};
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
	json_get_string((const char *) jp.hdr_json, jp.hdr_len, "kid", kid, sizeof(kid));
	if (strcmp(alg, "none") == 0 || strncmp(alg, "HS", 2) == 0)
		return true;
	if (strcmp(alg, "RS256") != 0 && strcmp(alg, "ES256") != 0 && strcmp(alg, "EdDSA") != 0)
		return true;

	pkey = load_pubkey_pem(g_pubkey_path);
	if (!pkey)
		pkey = load_pubkey_from_jwks(g_jwks_path, alg, kid);
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

	if (!json_get_string((const char *) jp.pay_json, jp.pay_len, "jti", jti, sizeof(jti)))
		return true;
	json_get_string((const char *) jp.pay_json, jp.pay_len, "tenant_id", tenant, sizeof(tenant));

	if (!issuer_allowed_for_tenant(iss, tenant))
		return true;
	if (jti_denied(jti))
		return true;
	/*
	 * Connect-time session check via auth-service-exported state file
	 * (no SQL from the validator). When configured, missing/revoked/unknown
	 * sessions fail closed here; RLS still re-checks every statement.
	 */
	if (!session_state_allows(sid, role))
		return true;

	jti_remember(jti);
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
	DefineCustomStringVariable("pg_appsec.oauth_session_state_file",
							   "JSON file of active/revoked sessions for connect-time checks",
							   NULL,
							   &g_session_state_file,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_jti_denylist_file",
							   "File listing denied JWT jti values",
							   NULL,
							   &g_jti_denylist_file,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomStringVariable("pg_appsec.oauth_issuer_map_file",
							   "Optional per-tenant issuer allowlist/map file",
							   NULL,
							   &g_issuer_map_file,
							   "",
							   PGC_SIGHUP,
							   0, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_appsec.oauth_session_state_max_age_secs",
							"Reject login if session-state file older than this many seconds (0 disables)",
							NULL,
							&g_session_state_max_age,
							120,
							0, 86400,
							PGC_SIGHUP,
							0, NULL, NULL, NULL);
}

__attribute__((visibility("default"))) PGDLLEXPORT const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &pg_appsec_callbacks;
}
