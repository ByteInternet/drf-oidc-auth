import sys

from authlib.jose.errors import BadSignatureError, DecodeError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import re_path as url
from oidc_auth.authentication import (BearerTokenAuthentication,
                                      JSONWebTokenAuthentication,
                                      JWTToken,
                                      UserInfo,)
from oidc_auth.test import AuthenticationTestCaseMixin, make_id_token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.views import APIView

if sys.version_info > (3,):
    long = int
else:
    class ConnectionError(OSError):
        pass

try:
    from unittest.mock import Mock, PropertyMock, patch
except ImportError:
    from mock import Mock, PropertyMock, patch


class TokenPermission(BasePermission):
    """Checks if the token has correct permissions"""

    def has_permission(self, request, _view):
        token = request.auth  # type: JWTToken
        if not token:
            return False
        if not isinstance(token, JWTToken) and not isinstance(token, UserInfo):
            return False
        return True

class MockView(APIView):
    permission_classes = (TokenPermission,)
    authentication_classes = (
        JSONWebTokenAuthentication,
        BearerTokenAuthentication
    )

    def get(self, request):
        return HttpResponse('a')


urlpatterns = [
    url(r'^test/$', MockView.as_view(), name="testview")
]


class TestBearerAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def setUp(self):
        super(TestBearerAuthentication, self).setUp()
        self.openid_configuration = {
            'issuer': 'http://accounts.example.com/dex',
            'authorization_endpoint': 'http://accounts.example.com/dex/auth',
            'token_endpoint': 'http://accounts.example.com/dex/token',
            'jwks_uri': 'http://accounts.example.com/dex/keys',
            'response_types_supported': ['code'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'scopes_supported': ['openid', 'email', 'groups', 'profile', 'offline_access'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic'],
            'claims_supported': [
                'aud', 'email', 'email_verified', 'exp', 'iat', 'iss', 'locale',
                'name', 'sub'
            ],
            'userinfo_endpoint': 'http://sellers.example.com/v1/sellers/'
        }

    def test_using_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.username})
        auth = 'Bearer abcdefg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a', resp.content)
        self.assertEqual(resp.status_code, 200, resp.content)
        self.mock_get.assert_called_with(
            'http://example.com/userinfo', headers={'Authorization': auth})

    def test_cache_of_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.username})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)

        # Token expires, but validity is cached
        self.responder.set_response('http://example.com/userinfo', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)

    def test_using_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer hjikasdf'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_cache_of_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/userinfo', "", 401)
        auth = 'Bearer feegrgeregreg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

        # Token becomes valid
        self.responder.set_response(
            'http://example.com/userinfo', {'sub': self.username})
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)

    def test_using_malformed_bearer_token(self):
        auth = 'Bearer abc def'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_using_missing_bearer_token(self):
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_using_inaccessible_userinfo_endpoint(self):
        self.mock_get.side_effect = ConnectionError
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_get_user_info_endpoint(self):
        authentication = BearerTokenAuthentication()
        response_mock = Mock(return_value=Mock(status_code=200,
                                                json=Mock(return_value={}),
                                                raise_for_status=Mock(return_value=None)))
        with patch('oidc_auth.authentication.requests.get', response_mock):
            result = authentication.get_userinfo(b'token')
            assert result == {}


class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.content.decode(), 'a', resp.content)

    def test_without_jwt(self):
        resp = self.client.get('/test/')
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_invalid_jwt(self):
        auth = 'JWT e30='
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_invalid_auth_header(self):
        auth = 'Bearer 12345'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_expired_jwt(self):
        auth = 'JWT ' + make_id_token(self.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_invalid_issuer(self):
        auth = 'JWT ' + \
               make_id_token(self.username, iss='http://something.com')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_invalid_audience(self):
        auth = 'JWT ' + make_id_token(self.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_too_new_jwt(self):
        auth = 'JWT ' + make_id_token(self.username, nbf=999999999999)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.username, aud=['you', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)

    def test_with_invalid_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.username, aud=['we', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401, resp.content)

    def test_with_multiple_audiences_and_authorized_party(self):
        auth = 'JWT ' + \
               make_id_token(self.username, aud=['you', 'me'], azp='you')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content)

    def test_with_invalid_signature(self):
        auth = 'JWT ' + make_id_token(self.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401, resp.content)

    @patch('oidc_auth.authentication.jwt.decode')
    @patch('oidc_auth.authentication.logger')
    def test_decode_jwt_logs_exception_message_when_decode_throws_exception(
        self,
        logger_mock, decode
    ):
        auth = 'JWT ' + make_id_token(self.username)
        decode.side_effect = DecodeError, BadSignatureError

        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)

        self.assertEqual(resp.status_code, 401, resp.content)
        logger_mock.exception.assert_called_once_with(
            'Invalid Authorization header. JWT Signature verification failed.')
