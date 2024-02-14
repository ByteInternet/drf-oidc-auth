import json
from requests.models import Response
from authlib.jose import JsonWebToken, KeySet, RSAKey
try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock
from cryptography.hazmat.primitives import serialization as crypto_serialization

jwt = JsonWebToken(['RS256', 'RS384', 'RS512'])

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

def make_id_token(sub="username",
                  iss='http://example.com',
                  aud='you',
                  exp=999999999999,  # tests will start failing in September 33658
                  iat=13151351,
                  nbf=13151351,
                  key=jwk_key,
                  kid=None,
                  **kwargs):
    payload = dict(
            iss=iss,
            aud=aud,
            exp=exp,
            iat=iat,
            nbf=nbf,
            sub=sub,
            **kwargs
        )
    # remove keys with empty values
    clean_payload = dict((k, v) for k, v in payload.items() if v)
    if kid is None:
        kid = key.as_dict(add_kid=True).get('kid')
    return make_jwt(clean_payload, key, kid).decode('ascii')


def make_local_token():
    return make_id_token(iss="local", key=pem_key, aud="local_aud")

def make_jwt(payload, key, kid):
    jws = jwt.encode(
        {'alg': 'RS256', 'kid': kid}, payload, key=key)
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

    def patch(self, thing_to_mock, **kwargs):
        patcher = patch(thing_to_mock, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def setUp(self):
        self.responder = FakeRequests()
        self.responder.set_response("http://example.com/.well-known/openid-configuration",
                                    {"jwks_uri": "http://example.com/jwks",
                                     "issuer": "http://example.com",
                                     "userinfo_endpoint": "http://example.com/userinfo"})
        self.mock_get = self.patch('requests.get')
        self.mock_get.side_effect = self.responder.get
        keys = KeySet(keys=[jwk_key])
        self.patch(
            'oidc_auth.authentication.request',
            return_value=Mock(
                status_code=200,
                json=keys.as_json
            )
        )
