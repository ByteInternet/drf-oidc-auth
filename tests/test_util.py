from random import random
from unittest import TestCase
from oidc_auth.util import cache


class TestCacheDecorator(TestCase):
    @cache(1)
    def mymethod(self, *args):
        return random()

    @cache(1)
    def failing(self):
        raise RuntimeError()

    @cache(0)
    def notcached(self):
        return random()

    @cache(1)
    def return_none(self):
        return None

    def test_that_result_of_method_is_memoized(self):
        x = self.mymethod('a')
        y = self.mymethod('b')
        self.assertEqual(x, self.mymethod('a'))
        self.assertEqual(y, self.mymethod('b'))
        self.assertNotEqual(x, y)

    def test_that_exceptions_are_raised(self):
        with self.assertRaises(RuntimeError):
            self.failing()

    def test_that_cache_is_disabled_with_low_ttl(self):
        x = self.notcached()
        # This will fail sometimes when the RNG returns two equal numbers...
        self.assertNotEqual(x, self.notcached())

    def test_that_cache_can_store_None(self):
        self.assertIsNone(self.return_none())
        self.assertIsNone(self.return_none())

    def test_that_expiration_works_as_expected(self):
        c = cache(10)
        c.add_to_cache(('abcde',), 'one', 5)
        c.add_to_cache(('fghij',), 'two', 6)
        c.add_to_cache(('klmno',), 'three', 7)
        self.assertEqual(c.get_from_cache(('abcde',)), 'one')
        self.assertEqual(c.get_from_cache(('fghij',)), 'two')
        self.assertEqual(c.get_from_cache(('klmno',)), 'three')
        c.purge_expired(14)
        self.assertEqual(c.get_from_cache(('abcde',)), 'one')
        c.purge_expired(16)
        self.assertRaises(KeyError, c.get_from_cache, ('abcde',))
        self.assertEqual(c.get_from_cache(('fghij',)), 'two')

        c.purge_expired(20)
        self.assertRaises(KeyError, c.get_from_cache, ('fghij',))
        self.assertRaises(KeyError, c.get_from_cache, ('klmno',))
