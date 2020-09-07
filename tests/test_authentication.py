import json
import sys

from django.conf.urls import url
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import TestCase
from requests import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from authlib.jose import JsonWebToken, KeySet, RSAKey
from oidc_auth.authentication import (BearerTokenAuthentication,
                                      JSONWebTokenAuthentication)

if sys.version_info > (3,):
    long = int
try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock


class MockView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (
        JSONWebTokenAuthentication,
        BearerTokenAuthentication
    )

    def get(self, request):
        return HttpResponse('a')


urlpatterns = [
    url(r'^test/$', MockView.as_view(), name="testview")
]

key = RSAKey.generate_key(is_private=True)


def make_jwt(payload):
    jwt = JsonWebToken(['RS256'])
    jws = jwt.encode(
        {'alg': 'RS256', 'kid': key.as_dict(add_kid=True).get('kid')}, payload, key=key)
    return jws


def make_id_token(sub,
                  iss='http://example.com',
                  aud='you',
                  exp=999999999999,  # tests will start failing in September 33658
                  iat=999999999999,
                  **kwargs):
    return make_jwt(
        dict(
            iss=iss,
            aud=aud,
            exp=exp,
            iat=iat,
            sub=str(sub),
            **kwargs
        )
    ).decode('ascii')


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


class AuthenticationTestCase(TestCase):
    urls = __name__

    def patch(self, thing_to_mock, **kwargs):
        patcher = patch(thing_to_mock, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def setUp(self):
        self.user = User.objects.create(username='henk')
        self.responder = FakeRequests()
        self.responder.set_response("http://example.com/.well-known/openid-configuration",
                                    {"jwks_uri": "http://example.com/jwks",
                                     "issuer": "http://example.com",
                                     "userinfo_endpoint": "http://example.com/userinfo"})
        self.mock_get = self.patch('requests.get')
        self.mock_get.side_effect = self.responder.get
        keys = KeySet(keys=[key])
        self.patch(
            'oidc_auth.authentication.request',
            return_value=Mock(
                status_code=200,
                json=keys.as_json
            )
        )


class TestBearerAuthentication(AuthenticationTestCase):
    def test_using_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        auth = 'Bearer abcdefg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a')
        self.assertEqual(resp.status_code, 200)
        self.mock_get.assert_called_with(
            'http://example.com/userinfo', headers={'Authorization': auth})

    def test_cache_of_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # Token expires, but validity is cached
        self.responder.set_response('http://example.com/userinfo', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_using_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer hjikasdf'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_cache_of_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer feegrgeregreg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

        # Token becomes valid
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.user.username})
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_using_malformed_bearer_token(self):
        auth = 'Bearer abc def'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_missing_bearer_token(self):
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_inaccessible_userinfo_endpoint(self):
        self.mock_get.side_effect = ConnectionError
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)


class TestJWTAuthentication(AuthenticationTestCase):
    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a')
        self.assertEqual(resp.status_code, 200)

    def test_without_jwt(self):
        resp = self.client.get('/test/')
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_jwt(self):
        auth = 'JWT e30='
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_auth_header(self):
        auth = 'Bearer 12345'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_expired_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_old_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, iat=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_issuer(self):
        auth = 'JWT ' + \
            make_id_token(self.user.username, iss='http://something.com')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_audience(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_too_new_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, nbf=999999999999)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_unknown_subject(self):
        auth = 'JWT ' + make_id_token(self.user.username + 'x')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud=['you', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud=['we', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences_and_authorized_party(self):
        auth = 'JWT ' + \
            make_id_token(self.user.username, aud=['you', 'me'], azp='you')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_signature(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401)
