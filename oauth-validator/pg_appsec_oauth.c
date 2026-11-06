/*
 * PostgreSQL 18 OAuth validator ABI skeleton.
 * This module intentionally rejects every token. Replace the validation
 * callback only after implementing the contract in README.md.
 */
#include "postgres.h"
#include "fmgr.h"
#include "fmgr.h"
#include "libpq/oauth.h"

PG_MODULE_MAGIC;

static bool
pg_appsec_validate(const ValidatorModuleState *state,
                   const char *token,
                   const char *role,
                   ValidatorModuleResult *result)
{
    (void) state;
    (void) token;
    (void) role;
    result->authorized = false;
    result->authn_id = NULL;
    return true;
}

static const OAuthValidatorCallbacks pg_appsec_callbacks = {
    .magic = PG_OAUTH_VALIDATOR_MAGIC,
    .startup_cb = NULL,
    .shutdown_cb = NULL,
    .validate_cb = pg_appsec_validate
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
    return &pg_appsec_callbacks;
}
