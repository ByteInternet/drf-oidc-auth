from heapq import heappop, heappush
import time


class ExpirationQueueElement(object):
    __slots__ = ('expiration', 'key')

    def __init__(self, expiration, key):
        self.expiration = expiration
        self.key = key

    def __lt__(self, other):
        return self.expiration < other.expiration


class cache(object):
    """ Cache decorator that memoizes the return value of a method for some time.
    """
    def __init__(self, ttl):
        self.ttl = ttl
        # Heap that contains keys in order of expiration
        self.expiration_queue = []
        self.cached_values = {}

    def purge_expired(self, now):
        while len(self.expiration_queue) > 0 and self.expiration_queue[0].expiration < now:
            expired = heappop(self.expiration_queue)
            del self.cached_values[expired.key]

    def add_to_cache(self, key, value, now):
        # import pdb; pdb.set_trace()
        # print("Adding %s to %s" % (key, self.cached_values))
        assert key not in self.cached_values, "Re-adding the same key breaks proper expiration"
        element = ExpirationQueueElement(now + self.ttl, key)
        self.cached_values[key] = value
        heappush(self.expiration_queue, element)

    def get_from_cache(self, key):
        return self.cached_values[key]

    def __call__(self, fn):
        def wrapped(this, *args):
            now = time.time()
            self.purge_expired(now)

            try:
                cached_value = self.get_from_cache(args)
            except KeyError:
                cached_value = fn(this, *args)
                self.add_to_cache(args, cached_value, now)

            return cached_value

        return wrapped
