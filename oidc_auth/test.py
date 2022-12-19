import json
import logging
from requests.models import Response
from authlib.jose import JsonWebToken, RSAKey
import jwt as pyjwt
try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock
from cryptography.hazmat.primitives import serialization as crypto_serialization

jwt = JsonWebToken(["RS256", "RS384", "RS512"])

logger = logging.getLogger(__name__)

jwk_key = RSAKey.generate_key(is_private=True)
pem_key = RSAKey.generate_key(is_private=True)

def get_public_key(key):
    """Returns public key for a RSAKey object"""
    public_key = key.get_public_key().public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format= crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return public_key

PEM_PUBLIC_KEY = get_public_key(pem_key)

def make_id_token(sub="user",
                  iss='http://example.com',
                  aud='you',
                  exp=999999999999,  # tests will start failing in September 33658
                  iat=999999999999,
                  nbf=13151351,
                  key=jwk_key,
                  include_kid=True,
                  kid=None,
                  **kwargs):
    payload = dict(
            iss=iss,
            aud=aud,
            exp=exp,
            iat=iat,
            nbf=nbf,
            sub=str(sub),
            **kwargs
    )
    # remove keys with empty values
    clean_payload = dict((k, v) for k, v in payload.items() if v)
    headers = {'alg': 'RS256'}
    if include_kid:
        headers['kid'] = kid if kid else key.as_dict(add_kid=True).get('kid')
    return make_jwt(clean_payload,headers,key).decode('ascii')

def make_local_token():
    return make_id_token(iss="local", key=pem_key, aud="local_aud")

def make_remote_token():
    return make_id_token()

def make_jwt(payload, headers, key):
    jws = jwt.encode(headers, payload, key=key)
    return jws

class FakeRequests(object):
    def __init__(self):
        self.responses = {}

    def set_response(self, url, content, status_code=200):
        self.responses[url] = (status_code, json.dumps(content))

    def get(self, url, *args, **kwargs):
        wanted_response = self.responses.get(url)
        if not wanted_response:
            status_code, content = 404, ''
        else:
            status_code, content = wanted_response

        response = Response()
        response._content = content.encode('utf-8')
        response.status_code = status_code

        return response

class AuthenticationTestCaseMixin(object):
    username = 'henk'

    def get_signing_key_mock(self, kid):
        if kid != jwk_key.as_dict(add_kid=True).get('kid'):
            raise pyjwt.exceptions.PyJWKClientError("Invalid Kid")
        key = get_public_key(jwk_key)
        return Mock(key=key)

    def patch(self, thing_to_mock, **kwargs):
        patcher = patch(thing_to_mock, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def setUp(self):
        self.patch(
            'oidc_auth.authentication.PyJWKClient',
            return_value=Mock(
                get_signing_key=self.get_signing_key_mock,
            )
        )
