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
#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#define JSMN_STATIC
#define JSMN_STRICT
#include "jsmn.h"

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
static int	g_session_state_max_bytes = 8 * 1024 * 1024;
static int	g_jti_max_entries = 100000;


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

/* ---- Strict session-state parsing (vendored jsmn v1.1.0, see jsmn.h) ---- */
#define SESSION_STATE_MAX_TOKENS 400000

static bool
jtok_eq(const char *buf, const jsmntok_t *t, const char *s)
{
	size_t		n = strlen(s);

	return t->type == JSMN_STRING && (size_t) (t->end - t->start) == n
		&& memcmp(buf + t->start, s, n) == 0;
}

/* Returns index after the subtree rooted at i, or -1 on structural error. */
static int
jtok_skip(const jsmntok_t *t, int i, int ntok)
{
	int			j,
				k,
				n;

	if (i < 0 || i >= ntok)
		return -1;
	n = t[i].size;
	j = i + 1;
	if (t[i].type == JSMN_OBJECT)
	{
		for (k = 0; k < n; k++)
		{
			if (j >= ntok || t[j].type != JSMN_STRING)
				return -1;
			j = jtok_skip(t, j + 1, ntok);
			if (j < 0)
				return -1;
		}
	}
	else if (t[i].type == JSMN_ARRAY)
	{
		for (k = 0; k < n; k++)
		{
			j = jtok_skip(t, j, ntok);
			if (j < 0)
				return -1;
		}
	}
	return j;
}

/* Strings in the state file must be plain (no escapes, no control chars). */
static bool
jtok_plain_string(const char *buf, const jsmntok_t *t)
{
	int			p;

	if (t->type != JSMN_STRING)
		return false;
	for (p = t->start; p < t->end; p++)
		if (buf[p] == '\\' || (unsigned char) buf[p] < 0x20)
			return false;
	return true;
}

static bool
jtok_is_null(const char *buf, const jsmntok_t *t)
{
	return t->type == JSMN_PRIMITIVE && t->end - t->start == 4
		&& memcmp(buf + t->start, "null", 4) == 0;
}

/* Array of plain strings; sets *hit if any element equals needle. */
static int
jparse_string_array(const char *buf, const jsmntok_t *t, int i, int ntok,
					const char *needle, bool *hit)
{
	int			k,
				j;

	if (i >= ntok || t[i].type != JSMN_ARRAY)
		return -1;
	j = i + 1;
	for (k = 0; k < t[i].size; k++)
	{
		if (j >= ntok || !jtok_plain_string(buf, &t[j]))
			return -1;
		if (needle && needle[0] && jtok_eq(buf, &t[j], needle))
			*hit = true;
		j++;
	}
	return j;
}

static int
jparse_active_sessions(const char *buf, const jsmntok_t *t, int i, int ntok,
					   const char *sid, const char *role, bool *hit)
{
	int			k,
				f,
				j;

	if (i >= ntok || t[i].type != JSMN_ARRAY)
		return -1;
	j = i + 1;
	for (k = 0; k < t[i].size; k++)
	{
		bool		have_sid = false,
					have_role = false,
					sid_ok = false,
					role_ok = false;
		int			nf;

		if (j >= ntok || t[j].type != JSMN_OBJECT)
			return -1;
		nf = t[j].size;
		j++;
		for (f = 0; f < nf; f++)
		{
			const jsmntok_t *key,
					   *val;

			if (j + 1 >= ntok || !jtok_plain_string(buf, &t[j]))
				return -1;
			key = &t[j];
			val = &t[j + 1];
			if (jtok_eq(buf, key, "sid") || jtok_eq(buf, key, "role"))
			{
				bool		is_sid = jtok_eq(buf, key, "sid");

				if (!jtok_plain_string(buf, val))
					return -1;
				if (is_sid)
				{
					if (have_sid)
						return -1;	/* duplicate key */
					have_sid = true;
					sid_ok = jtok_eq(buf, val, sid);
				}
				else
				{
					if (have_role)
						return -1;
					have_role = true;
					role_ok = jtok_eq(buf, val, role);
				}
			}
			else if (jtok_eq(buf, key, "user_id") || jtok_eq(buf, key, "tenant_id")
					 || jtok_eq(buf, key, "expires_at") || jtok_eq(buf, key, "jti"))
			{
				if (!jtok_plain_string(buf, val) && !jtok_is_null(buf, val))
					return -1;
			}
			else
				return -1;		/* unknown key: strict schema */
			j += 2;
		}
		if (!have_sid || !have_role)
			return -1;
		if (sid_ok && role_ok)
			*hit = true;
	}
	return j;
}

static bool
parse_generated_at(const char *buf, const jsmntok_t *t, time_t *out)
{
	char		tsbuf[64];
	struct tm	tm;
	int			len = t->end - t->start;

	if (!jtok_plain_string(buf, t) || len < 19 || len >= (int) sizeof(tsbuf))
		return false;
	memcpy(tsbuf, buf + t->start, (size_t) len);
	tsbuf[len] = '\0';
	/* Require UTC: trailing Z or +00:00 / +00 */
	if (!(tsbuf[len - 1] == 'Z' || (len >= 6 && strcmp(tsbuf + len - 6, "+00:00") == 0)
		  || (len >= 3 && strcmp(tsbuf + len - 3, "+00") == 0)))
		return false;
	tsbuf[19] = '\0';
	memset(&tm, 0, sizeof(tm));
	if (strptime(tsbuf, "%Y-%m-%dT%H:%M:%S", &tm) == NULL)
		return false;
	*out = timegm(&tm);
	return *out > 0;
}

/*
 * Fail-closed connect-time check. Schema (all keys required, no others):
 *   {"generated_at": "<RFC3339 UTC>",
 *    "active_sessions": [{"sid","role", optional user_id/tenant_id/expires_at/jti}],
 *    "revoked_sids": ["..."], "denied_jtis": ["..."]}
 */
static bool
session_state_allows(const char *sid, const char *role, const char *jti)
{
	FILE	   *f;
	char	   *buf;
	long		sz;
	struct stat st;
	time_t		now,
				generated = 0;
	jsmn_parser p;
	jsmntok_t  *t;
	int			ntok,
				i,
				k,
				j;
	bool		seen_gen = false,
				seen_act = false,
				seen_rev = false,
				seen_den = false;
	bool		active_hit = false,
				revoked_hit = false,
				jti_hit = false;
	bool		ok = false;

	/* If no state file configured, allow (RLS still enforces post-connect). */
	if (!g_session_state_file || g_session_state_file[0] == '\0')
		return true;
	if (stat(g_session_state_file, &st) != 0)
		return false;
	now = time(NULL);
	if (g_session_state_max_age > 0
		&& st.st_mtime + g_session_state_max_age < now)
		return false;			/* fail closed: sync worker stale */
	if (st.st_size <= 0 || st.st_size > (off_t) g_session_state_max_bytes)
		return false;			/* fail closed: empty or oversized */
	f = fopen(g_session_state_file, "r");
	if (!f)
		return false;
	if (fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return false;
	}
	sz = ftell(f);
	if (sz <= 0 || sz > (long) g_session_state_max_bytes)
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
	if (memchr(buf, '\0', (size_t) sz) != NULL)
	{
		pfree(buf);
		return false;
	}

	jsmn_init(&p);
	ntok = jsmn_parse(&p, buf, (size_t) sz, NULL, 0);
	if (ntok <= 0 || ntok > SESSION_STATE_MAX_TOKENS)
	{
		pfree(buf);
		return false;			/* malformed or too many tokens */
	}
	t = palloc(sizeof(jsmntok_t) * (size_t) ntok);
	jsmn_init(&p);
	if (jsmn_parse(&p, buf, (size_t) sz, t, (unsigned int) ntok) != ntok
		|| t[0].type != JSMN_OBJECT
		|| jtok_skip(t, 0, ntok) != ntok)
		goto done;				/* trailing values / structure error */
	for (i = t[0].end; i < sz; i++)
		if (!isspace((unsigned char) buf[i]))
			goto done;

	j = 1;
	for (k = 0; k < t[0].size; k++)
	{
		if (j + 1 >= ntok || !jtok_plain_string(buf, &t[j]))
			goto done;
		if (jtok_eq(buf, &t[j], "generated_at"))
		{
			if (seen_gen || !parse_generated_at(buf, &t[j + 1], &generated))
				goto done;
			seen_gen = true;
			j += 2;
		}
		else if (jtok_eq(buf, &t[j], "active_sessions"))
		{
			if (seen_act)
				goto done;
			seen_act = true;
			j = jparse_active_sessions(buf, t, j + 1, ntok, sid, role, &active_hit);
		}
		else if (jtok_eq(buf, &t[j], "revoked_sids"))
		{
			if (seen_rev)
				goto done;
			seen_rev = true;
			j = jparse_string_array(buf, t, j + 1, ntok, sid, &revoked_hit);
		}
		else if (jtok_eq(buf, &t[j], "denied_jtis"))
		{
			if (seen_den)
				goto done;
			seen_den = true;
			j = jparse_string_array(buf, t, j + 1, ntok, jti, &jti_hit);
		}
		else
			goto done;			/* unknown top-level key */
		if (j < 0)
			goto done;
	}
	if (!seen_gen || !seen_act || !seen_rev || !seen_den)
		goto done;
	if (g_session_state_max_age > 0 && generated + g_session_state_max_age < now)
		goto done;
	if (generated > now + g_clock_skew)
		goto done;				/* future-dated state is suspicious */
	ok = active_hit && !revoked_hit && !jti_hit;
done:
	pfree(t);
	pfree(buf);
	return ok;
}

/*
 * jti seen/deny file: one entry per line, "<jti> <exp_unix>" (exp optional
 * = permanent). Exact match only. Expired entries are pruned on every
 * successful login; if more than g_jti_max_entries unexpired entries would
 * remain, login fails closed.
 */
static bool
jti_line_parse(char *line, char **jti_out, int64_t *exp_out)
{
	char	   *sp;
	char	   *end;
	size_t		n = strlen(line);

	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' '))
		line[--n] = '\0';
	if (n == 0)
		return false;
	sp = strchr(line, ' ');
	*exp_out = INT64_MAX;
	if (sp)
	{
		*sp = '\0';
		errno = 0;
		*exp_out = strtoll(sp + 1, &end, 10);
		if (errno != 0 || *end != '\0' || end == sp + 1)
			*exp_out = INT64_MAX;	/* unparsable exp: keep (fail closed) */
	}
	*jti_out = line;
	return line[0] != '\0';
}

static bool
jti_denied(const char *jti)
{
	FILE	   *f;
	char		line[MAX_CLAIM + 64];
	time_t		now = time(NULL);
	long		count = 0;

	if (!jti || jti[0] == '\0')
		return true;
	if (!g_jti_denylist_file || g_jti_denylist_file[0] == '\0')
		return false;
	f = fopen(g_jti_denylist_file, "r");
	if (!f)
		return errno != ENOENT;	/* unreadable → fail closed */
	while (fgets(line, sizeof(line), f))
	{
		char	   *e;
		int64_t		exp;

		if (strchr(line, '\n') == NULL && !feof(f))
		{
			fclose(f);
			return true;		/* over-long line: fail closed */
		}
		if (!jti_line_parse(line, &e, &exp))
			continue;
		if (++count > (long) g_jti_max_entries * 4)
		{
			fclose(f);
			return true;		/* runaway file: fail closed */
		}
		if (exp + g_clock_skew >= (int64_t) now && strcmp(e, jti) == 0)
		{
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

/* Prune expired + append; false → fail closed (cap exceeded / IO error). */
static bool
jti_remember(const char *jti, int64_t exp)
{
	char		lockpath[MAXPGPATH];
	char		tmppath[MAXPGPATH];
	char		line[MAX_CLAIM + 64];
	int			lfd;
	FILE	   *in,
			   *out;
	long		kept = 0;
	bool		ok = false;
	time_t		now = time(NULL);

	if (!g_jti_denylist_file || g_jti_denylist_file[0] == '\0')
		return true;
	snprintf(lockpath, sizeof(lockpath), "%s.lock", g_jti_denylist_file);
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", g_jti_denylist_file, (int) getpid());
	lfd = open(lockpath, O_RDWR | O_CREAT, 0600);
	if (lfd < 0)
		return false;
	if (flock(lfd, LOCK_EX) != 0)
	{
		close(lfd);
		return false;
	}
	out = fopen(tmppath, "w");
	if (!out)
		goto unlock;
	in = fopen(g_jti_denylist_file, "r");
	if (in)
	{
		while (fgets(line, sizeof(line), in))
		{
			char	   *e;
			int64_t		le;

			if (!jti_line_parse(line, &e, &le))
				continue;
			if (le != INT64_MAX && le + g_clock_skew < (int64_t) now)
				continue;		/* prune expired */
			if (strcmp(e, jti) == 0)
			{
				fclose(in);
				goto abort_tmp;	/* raced replay */
			}
			if (++kept >= (long) g_jti_max_entries)
			{
				fclose(in);
				goto abort_tmp;	/* cap exceeded: fail closed */
			}
			if (le == INT64_MAX)
				fprintf(out, "%s\n", e);
			else
				fprintf(out, "%s %lld\n", e, (long long) le);
		}
		fclose(in);
	}
	else if (errno != ENOENT)
		goto abort_tmp;
	fprintf(out, "%s %lld\n", jti, (long long) exp);
	if (fflush(out) != 0 || fsync(fileno(out)) != 0)
		goto abort_tmp;
	if (fclose(out) != 0)
	{
		out = NULL;
		goto abort_tmp;
	}
	out = NULL;
	if (rename(tmppath, g_jti_denylist_file) != 0)
		goto abort_tmp;
	ok = true;
	goto unlock;
abort_tmp:
	if (out)
		fclose(out);
	unlink(tmppath);
unlock:
	flock(lfd, LOCK_UN);
	close(lfd);
	return ok;
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
	if (!session_state_allows(sid, role, jti))
		return true;
	if (!jti_remember(jti, exp))
		return true;			/* cap exceeded / IO error: fail closed */
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
	DefineCustomIntVariable("pg_appsec.oauth_session_state_max_bytes",
							"Reject login if session-state file is larger than this (fail closed)",
							NULL,
							&g_session_state_max_bytes,
							8 * 1024 * 1024,
							1024, 256 * 1024 * 1024,
							PGC_SIGHUP,
							0, NULL, NULL, NULL);
	DefineCustomIntVariable("pg_appsec.oauth_jti_max_entries",
							"Max unexpired jti entries kept; login fails closed when exceeded",
							NULL,
							&g_jti_max_entries,
							100000,
							1, 10000000,
							PGC_SIGHUP,
							0, NULL, NULL, NULL);
}

__attribute__((visibility("default"))) PGDLLEXPORT const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &pg_appsec_callbacks;
}
