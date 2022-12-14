# OpenID Connect authentication for Django Rest Framework

This is a fork of the original [OpenID Connect authentication for Django Rest Framework
by ByteInternet ](https://github.com/Uninett/drf-oidc-auth).

This package contains authentication mechanisms for authenticating
JWT tokens. Multiple issuers are allowed, and for each issuer
a key source must be defined. The key source can either be a
JWKS endpoint, or a string containing a public key in PEM format.

This implementation does not rely on the Django user system, but
can be configured to authenticate as a user based on the contents
of the token.

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
    ),
    'UNAUTHENTICATED_USER': None,
}
```

These can also be set manually for the API view, it does not have to be
registered as the default authentication classes.

And configure the module itself in settings.py:
```py
OIDC_AUTH = {
    # The Claims Options can now be defined by a static string.
    # It is recommended to set a required value for the 'aud' claim.
    # The ISSUERS setting is used to configure the 'iss' claim option,
    # so setting the 'iss' claim here will override this automatic configuration.
    # ref: https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'essential': True,
            'value': "your-service-name",
        },
        'nbf': {
            'essential': True,
        },
    },
    # Dict of issuers mapping to key source. key can either be type PEM, then the key value
    # should be a string containing a public key in PEM format. if type is JWKS, then key should
    # a url for a JWKS endpoint
    'ISSUERS': {
        'issuer1': {
            'type': "PEM",
            'key': """-----BEGIN RSA PUBLIC KEY-----
publickeydatahere..
-----END RSA PUBLIC KEY-----"""
        },
        'issuer2': {
            'type': "JWKS",
            'key': "http://example.com/openid/jwks"
        }
    },

    # (Optional) Function that resolves id_token into user.
    # This function receives a request and an id_token dict and expects to
    # return a User object. The default implementation returns None.
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_none',

    # (Optional) Time before signing keys will be refreshed (default 24 hrs)
    'OIDC_JWKS_EXPIRATION_TIME': 24*60*60,

    # (Optional) Token prefix in JWT authorization header (default 'JWT')
    'JWT_AUTH_HEADER_PREFIX': 'JWT',

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

class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), 'a')

    def test_without_jwt(self):
        resp = self.client.get('/test/')
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_jwt(self):
        auth = 'JWT e30='
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
```

# References

* Requires [Django REST Framework](http://www.django-rest-framework.org/)
* And of course [Django](https://www.djangoproject.com/)
* Inspired on [REST framework JWT Auth](https://github.com/GetBlimp/django-rest-framework-jwt)
* Fork of [OpenID Connect authentication for Django Rest Framework](https://github.com/Uninett/drf-oidc-auth)
