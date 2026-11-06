#ifndef PG_APPSEC_OAUTH_ABI_H
#define PG_APPSEC_OAUTH_ABI_H
/* Minimal copy of PostgreSQL 18 OAuth validator ABI (libpq/oauth.h). */
#include "postgres.h"

typedef struct ValidatorModuleState
{
	int			sversion;
	void	   *private_data;
} ValidatorModuleState;

typedef struct ValidatorModuleResult
{
	bool		authorized;
	char	   *authn_id;
} ValidatorModuleResult;

typedef void (*ValidatorStartupCB) (ValidatorModuleState *state);
typedef void (*ValidatorShutdownCB) (ValidatorModuleState *state);
typedef bool (*ValidatorValidateCB) (const ValidatorModuleState *state,
									 const char *token, const char *role,
									 ValidatorModuleResult *result);

#define PG_OAUTH_VALIDATOR_MAGIC 0x20250220

typedef struct OAuthValidatorCallbacks
{
	uint32		magic;
	ValidatorStartupCB startup_cb;
	ValidatorShutdownCB shutdown_cb;
	ValidatorValidateCB validate_cb;
} OAuthValidatorCallbacks;

typedef const OAuthValidatorCallbacks *(*OAuthValidatorModuleInit) (void);
#endif
