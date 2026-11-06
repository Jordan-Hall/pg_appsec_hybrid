/* Minimal libpq OAuth bearer injector for pg_appsec_oauth E2E tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libpq-fe.h"

static char *g_token = NULL;

static int
auth_hook(PGauthData type, PGconn *conn, void *data)
{
	if (type == PQAUTHDATA_OAUTH_BEARER_TOKEN)
	{
		PGoauthBearerRequest *req = data;
		req->token = g_token;
		return 1; /* handled */
	}
	return 0;
}

int
main(int argc, char **argv)
{
	PGconn	   *conn;
	PGresult   *res;
	const char *kw[] = {"host", "port", "dbname", "user", "oauth_issuer", "oauth_client_id", NULL};
	const char *vals[6];

	if (argc < 6)
	{
		fprintf(stderr, "usage: %s host port dbname user token_file\n", argv[0]);
		return 2;
	}
	{
		FILE	   *f = fopen(argv[5], "r");
		char		buf[16384];
		size_t		n;

		if (!f)
		{
			perror("token");
			return 2;
		}
		n = fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);
		buf[n] = '\0';
		while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
			buf[--n] = '\0';
		g_token = strdup(buf);
	}
	vals[0] = argv[1];
	vals[1] = argv[2];
	vals[2] = argv[3];
	vals[3] = argv[4];
	vals[4] = "https://pg-appsec.test";
	vals[5] = "pg_appsec_test_client";

	PQsetAuthDataHook(auth_hook);
	conn = PQconnectdbParams(kw, vals, 0);
	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "CONNECT_FAIL: %s\n", PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}
	res = PQexec(conn, "select session_user, current_user");
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		fprintf(stderr, "QUERY_FAIL: %s\n", PQerrorMessage(conn));
		PQclear(res);
		PQfinish(conn);
		return 1;
	}
	printf("OK session_user=%s current_user=%s\n", PQgetvalue(res, 0, 0), PQgetvalue(res, 0, 1));
	PQclear(res);
	PQfinish(conn);
	return 0;
}
