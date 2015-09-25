# OpenID Connect authentication for Django Rest Framework

This package contains an authentication mechanism for authenticating 
users of a REST API using tokens obtained from OpenID Connect.

Currently, it only supports JWT tokens, which will be validated against 
the public keys of an OpenID connect authorization service.

In the future this might be expanded to accepting bearer (access) tokens 
from the authentication service, but since there is no standardized way 
of verifying these bearer tokens against the auth server this is omitted 
for now. 

# Installation

Install using pip:

```sh
pip install drf-oidc-auth
```

Configure authentication for Django REST Framework in settings.py:

```py
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # ...
        'oidc_auth.authentication.JSONWebTokenAuthentication',
    ),
}
```

And configure the module itself in settings.py:
```py
OIDC_AUTH = {
    # Specify OpenID Connect endpoint. Configuration will be
    # automatically done based on the discovery document found
    # at <endpoint>/.well-known/openid-configuration
    'OIDC_ENDPOINT': 'https://accounts.google.com',

    # Accepted audiences the ID Tokens can be issued to
    'OIDC_AUDIENCE': 'myapp',
    
    # (Optional) Function that resolves id_token into user.
    # This function receives an id_token dict and expects to return
    # a User object. The default implementation tries to find the user
    # based on username (natural key) taken from the 'sub'-claim of the
    # id_token.
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_by_id',
    
    # (Optional) Number of seconds in the past valid tokens can be 
    # issued (default 600)
    'OIDC_LEEWAY': 600,
    
    # (Optional) Time before signing keys will be refreshed (default 24 hrs)
    'OIDC_JWKS_EXPIRATION_TIME': 24*60*60
    
    # (Optional) Token prefix in authorization header (default 'JWT')
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
}
```

# Running tests

```sh
pip install tox
tox
```

# References

* Requires [Django REST Framework](http://www.django-rest-framework.org/)
* And of course [Django](https://www.djangoproject.com/)
* Inspired on [REST framework JWT Auth](https://github.com/GetBlimp/django-rest-framework-jwt)
