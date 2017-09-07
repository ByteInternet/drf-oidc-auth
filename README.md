# 07-Sept-2017
* Replaced `User.objects.get_by_natural_key` with `User.objects.get_or_create`
* Forced username to lower case to be consistent with django-auth-ldap
* Requesting pull to the original project.
* Otherwise, awesome project from which this was forked!! Thank you [ByteInternet](https://github.com/ByteInternet/drf-oidc-auth)

# OpenID Connect authentication for Django Rest Framework

This package contains an authentication mechanism for authenticating 
users of a REST API using tokens obtained from OpenID Connect.

Currently, it only supports JWT and Bearer tokens. JWT tokens will be 
validated against the public keys of an OpenID connect authorization 
service. Bearer tokens are used to retrieve the OpenID UserInfo for a
user to identify him.

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
        'oidc_auth.authentication.BearerTokenAuthentication',
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
    'OIDC_AUDIENCES': ('myapp',),
    
    # (Optional) Function that resolves id_token into user.
    # This function receives a request and an id_token dict and expects to
    # return a User object. The default implementation tries to find the user
    # based on username (natural key) taken from the 'sub'-claim of the
    # id_token.
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_by_id',
    
    # (Optional) Number of seconds in the past valid tokens can be 
    # issued (default 600)
    'OIDC_LEEWAY': 600,
    
    # (Optional) Time before signing keys will be refreshed (default 24 hrs)
    'OIDC_JWKS_EXPIRATION_TIME': 24*60*60,

    # (Optional) Time before bearer token validity is verified again (default 10 minutes)
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 10*60,
    
    # (Optional) Token prefix in JWT authorization header (default 'JWT')
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    
    # (Optional) Token prefix in Bearer authorization header (default 'Bearer')
    'BEARER_AUTH_HEADER_PREFIX': 'Bearer',
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
