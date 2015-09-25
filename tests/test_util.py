from random import random
from unittest import TestCase
from oidc_auth.util import cache


class TestCacheDecorator(TestCase):
    @cache(1)
    def mymethod(self):
        return random()

    @cache(1)
    def failing(self):
        raise RuntimeError()

    @cache(0)
    def notcached(self):
        return random()

    def test_that_result_of_method_is_memoized(self):
        x = self.mymethod()
        self.assertEqual(x, self.mymethod())

    def test_that_exceptions_are_raised_first_time(self):
        with self.assertRaises(RuntimeError):
            self.failing()

    def test_that_cache_is_disabled_with_low_ttl(self):
        x = self.notcached()
        # This will fail sometimes when the RNG returns two equal numbers...
        self.assertNotEqual(x, self.notcached())

    def disabled_slow_test_that_last_cache_value_is_preserved_if_subsequent_calls_fail(self):
        from time import sleep
        runs = [0]  # Store runs in array so it can be changed within m()
        @cache(1)
        def m(self):
            if runs[0] > 0:
                raise RuntimeError()
            runs[0] += 1
            return random()

        x = m(self)
        self.assertEqual(x, m(self))
        sleep(1)
        self.assertEqual(x, m(self))
