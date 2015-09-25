import time


class cache(object):
    """ Cache decorator that memoizes the last return value of a method for
    some time.

    WARNING: If the method raises an exception on subsequent calls it will be
    swallowed, returning the previous successful value.

    WARNING2: Two instances of the class that
    """
    def __init__(self, ttl):
        self.ttl = ttl
        self.cached_value = None
        self.last_updated = None

    def __call__(self, fn):
        def wrapped(this):
            now = time.time()
            if not self.cached_value or now - self.last_updated > self.ttl:
                try:
                    self.cached_value = fn(this)
                    self.last_updated = now
                except:
                    if not self.cached_value:
                        raise

            return self.cached_value
        return wrapped
