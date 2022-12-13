from oidc_auth.test import PUBLIC_KEY
SECRET_KEY = 'secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
REST_FRAMEWORK = {
    'UNAUTHENTICATED_USER': None,
}
ROOT_URLCONF = 'tests.test_authentication'
OIDC_AUTH = {
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'essential': True,
            'values': ['you'],
        }
    },
    'ISSUERS': {
        'http://example.com': {
            'type': "JWKS",
            'key': "http://example.com"
        },
        'local': {
            'type': "PEM",
            'key': PUBLIC_KEY,
        }
    },
}
