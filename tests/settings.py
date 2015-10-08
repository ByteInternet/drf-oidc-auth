SECRET_KEY='secret'
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
ROOT_URLCONF = 'urls'
OIDC_AUTH = {
    'OIDC_ENDPOINT': 'http://example.com',
    'OIDC_AUDIENCES': ('you',),
}
