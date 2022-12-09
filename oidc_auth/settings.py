from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'OIDC_AUTH', None)

DEFAULTS = {
    # Dict of issuers mapping to key source. key can either be type PEM, then the key value
    # should be a string containing a public key in PEM format. if type is JWKS, then key should
    # a url for a JWKS endpoint
    'ISSUERS': {},

    # Will only accept tokens with 'aud' claim that matches a string in this list
    'AUDIENCES': None,

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
