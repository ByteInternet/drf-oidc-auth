SECRET_KEY = 'secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
INSTALLED_APPS = (
)
REST_FRAMEWORK = {
    'UNAUTHENTICATED_USER': None,
}
ROOT_URLCONF = 'tests.test_authentication'
OIDC_AUTH = {
    'OIDC_ENDPOINT': 'http://example.com',
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'values': ['you'],
            'essential': True,
        }
    },
}
