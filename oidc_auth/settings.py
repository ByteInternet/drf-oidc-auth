from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'OIDC_AUTH', None)

DEFAULTS = {
    'OIDC_ENDPOINT': None,

    # Currently unimplemented
    'OIDC_ENDPOINTS': [],

    # The Claims Options can now be defined by a static string.
    # ref: https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'essential': True,
        }
    },

    # Time before JWKS will be refreshed
    'OIDC_JWKS_EXPIRATION_TIME': 24 * 60 * 60,

    # Function to resolve user from request and token or userinfo
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_none',

    # Time before bearer token validity is verified again
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 600,

    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'BEARER_AUTH_HEADER_PREFIX': 'Bearer',

    # The Django cache to use
    'OIDC_CACHE_NAME': 'default',
    'OIDC_CACHE_PREFIX': 'oidc_auth.',

    # URL of the OpenID Provider's UserInfo Endpoint
    'USERINFO_ENDPOINT': None,
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'OIDC_RESOLVE_USER_FUNCTION',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
