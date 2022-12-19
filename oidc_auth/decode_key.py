import logging

import jwt
from jwt import PyJWKClient
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache


logger = logging.getLogger(__name__)

class DecodeKey(object):
    key_source = None
    token = None

    def __init__(self, token, key_source):
        self.key_source = key_source
        self.token = token

    @property
    def key(self):
        """Returns a key for use with jwt.decode from the PyJWT lib"""
        pass

class PEMDecodeKey(DecodeKey):

    @property
    def key(self):
        return self.key_source

class JWKSDecodeKey(DecodeKey):

    @property
    def key(self):
        kid = self._get_kid(self.token)
        key = self._get_jwks_key(self.key_source, kid)
        return key

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def _get_jwks_key(self, jwks_endpoint, kid):
        jwks_client = PyJWKClient(jwks_endpoint)
        signing_key = jwks_client.get_signing_key(kid)
        return signing_key.key

    def _get_kid(self, token):
        """Gets the kid value from the header of a raw token"""
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise AuthenticationFailed("Token must include the 'kid' header")
        return kid
