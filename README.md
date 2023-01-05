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
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # ...
        'oidc_auth.authentication.JSONWebTokenAuthentication',
        'oidc_auth.authentication.BearerTokenAuthentication',
    ),
    'UNAUTHENTICATED_USER': None,
}
```

These can also be set manually for the API view, it does not have to be
registered as the default authentication classes.

And configure the module itself in settings.py:
```py
OIDC_AUTH = {
    # Define multiple issuers in here, each with
    # an `type`, `key` and `claims_options` value.
    # The key for each issuer in the dict will be the expected value for
    # the 'iss' claim in tokens from that issuer.
    # `claims_options` can now be defined according to this documentation:
    # ref: https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
    # `type` can be "PEM" or "JWKS". If "PEM", then `key` must be a public key
    # in PEM format. if "JWKS`, then `key` must be a JWKS endpoint
    # `aud` is only required, when you set it as an essential claim.
    'JWT_ISSUERS': {
        'https://google.com': {
            'type': 'JWKS',
            'key': 'https://accounts.google.com',
            'claims_options': {
                'aud': {
                    'values': ['myapp']
                    'essential': True,
                }
            },
        }
    }

    # (Optional) Function that resolves id_token into user.
    # This function receives a request and an id_token dict and expects to
    # return a User object. The default implementation tries to find the user
    # based on username (natural key) taken from the 'sub'-claim of the
    # id_token.
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_none',

    # (Optional) Time before signing keys will be refreshed (default 24 hrs)
    'JWKS_EXPIRATION_TIME': 24*60*60,

    # (Optional) Time before bearer token validity is verified again (default 10 minutes)
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 10*60,

    # (Optional) Token prefix in JWT authorization header (default 'JWT')
    'JWT_AUTH_HEADER_PREFIX': 'JWT',

    # (Optional) Token prefix in Bearer authorization header (default 'Bearer')
    'BEARER_AUTH_HEADER_PREFIX': 'Bearer',

    # (Optional) Which Django cache to use
    'OIDC_CACHE_NAME': 'default',

    # (Optional) A cache key prefix when storing and retrieving cached values
    'OIDC_CACHE_PREFIX': 'oidc_auth.',
}
```

## User authentication

By default, this plugin does not authenticate a user. As long as the token itself is validated succesfully,
it will be a success. This will cause problems if your permission classes require a user to be authenticated,
or your API in general requires a User to be authenticated. In order to authenticate a user, a custom
function can be defined in the
`OIDC_RESOLVE_USER_FUNCTION` setting. An example can look like this:

```
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed

def get_user_by_id(request, id_token)
    User = get_user_model()
    try:
        user = User.objects.get(username=id_token.get('sub'))
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user

```

This will authenticate as the user with a username matching the `sub` claim in the token. If no such user
exists, the authentication fails. Using the Django user models will require the `django.contrib.auth`
and`django.contrib.contenttypes` apps to be configured in the django `settings.py` file like so:

```
INSTALLED_APPS = (
    #  ...
    'django.contrib.auth',
    'django.contrib.contenttypes',
)
```


# Running tests

```sh
pip install tox
tox
```

## Mocking authentication

There's a `AuthenticationTestCaseMixin` provided in the `oidc_auth.test` module, which you
can use for testing authentication like so:
```python
from oidc_auth.test import AuthenticationTestCaseMixin
from django.test import TestCase

class MyTestCase(AuthenticationTestCaseMixin, TestCase):
    def test_example_cache_of_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.username})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # Token expires, but validity is cached
        self.responder.set_response('http://example.com/userinfo', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_example_using_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer hjikasdf'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
```

# References

* Requires [Django REST Framework](http://www.django-rest-framework.org/)
* And of course [Django](https://www.djangoproject.com/)
* Inspired on [REST framework JWT Auth](https://github.com/GetBlimp/django-rest-framework-jwt)
