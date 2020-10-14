SECRET_KEY = 'secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
)
ROOT_URLCONF = 'tests.test_authentication'
OIDC_AUTH = {
    'OIDC_ENDPOINT': 'http://example.com',
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'values': ['you'],
        }
    },
}
