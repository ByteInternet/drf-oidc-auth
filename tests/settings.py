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
    'OIDC_ENDPOINT': 'http://example.com',
    'JWKS_ENDPOINT': 'http://example.com',
    'AUDIENCE': 'you',
    'ISSUER': 'http://example.com',
}
