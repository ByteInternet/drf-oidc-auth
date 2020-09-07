import functools

from django.core.cache import caches

from .settings import api_settings


class cache(object):
    """ Cache decorator that memoizes the return value of a method for some time.

    Increment the cache_version everytime your method's implementation changes 
    in such a way that it returns values that are not backwards compatible.
    For more information, see the Django cache documentation:
    https://docs.djangoproject.com/en/2.2/topics/cache/#cache-versioning
    """

    def __init__(self, ttl, cache_version=1):
        self.ttl = ttl
        self.cache_version = cache_version

    def __call__(self, fn):
        @functools.wraps(fn)
        def wrapped(this, *args):
            cache = caches[api_settings.OIDC_CACHE_NAME]
            key = api_settings.OIDC_CACHE_PREFIX + '.'.join([fn.__name__] + list(map(str, args)))
            cached_value = cache.get(key, version=self.cache_version)
            if not cached_value:
                cached_value = fn(this, *args)
                cache.set(key, cached_value, timeout=self.ttl, version=self.cache_version)
            return cached_value

        return wrapped
