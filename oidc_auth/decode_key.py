from requests import request

from authlib.jose import JsonWebKey

from .settings import api_settings
from .util import cache

class DecodeKey(object):
    key_source = None

    def __init__(self, key_source):
        self.key_source = key_source

    @property
    def key(self):
        """Returns a key for use with authlib.jose.jwt.decode"""
        pass

class PEMDecodeKey(DecodeKey):

    @property
    def key(self):
        return bytes(self.key_source, encoding='UTF-8')

class JWKSDecodeKey(DecodeKey):

    @property
    def key(self):
        return JsonWebKey.import_key_set(self.jwks_data())

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        r = request("GET", self.key_source, allow_redirects=True)
        r.raise_for_status()
        return r.json()
