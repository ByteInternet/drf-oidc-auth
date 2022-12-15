from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'OIDC_AUTH', None)

DEFAULTS = {
    # Dict of issuers mapping to key source. `type` can be either `PEM` or `JWKS`. If `PEM`, then the `key` value
    # should be a string containing a public key in PEM format. For `JWKS` it should be the URL for a JWKS endpoint.
    # `aud` must also be configured per issuer. This should match the value the token issuer sets for the `aud` claim
    # in the issued tokens.
    'ISSUERS': {},

    # Time before JWKS will be refreshed
    'OIDC_JWKS_EXPIRATION_TIME': 24 * 60 * 60,

    # Function to resolve user from request and token or userinfo
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_none',

    # (Optional) Token prefix in JWT authorization header (default 'JWT')
    'JWT_AUTH_HEADER_PREFIX': 'JWT',

    # The Django cache to use
    'OIDC_CACHE_NAME': 'default',
    'OIDC_CACHE_PREFIX': 'oidc_auth.',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'OIDC_RESOLVE_USER_FUNCTION',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
