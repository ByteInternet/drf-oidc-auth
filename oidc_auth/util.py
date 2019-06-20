import functools

from django.core.cache import caches
from .settings import api_settings


class cache(object):
    """ Cache decorator that memoizes the return value of a method for some time.
    """
    cache_version = 1

    def __init__(self, ttl):
        self.ttl = ttl

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
