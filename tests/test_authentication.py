import sys

from authlib.jose.errors import BadSignatureError, DecodeError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import re_path as url
from oidc_auth.authentication import (BearerTokenAuthentication,
                                      JSONWebTokenAuthentication)
from oidc_auth.test import AuthenticationTestCaseMixin, make_id_token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
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

    def test_get_user_info_endpoint(self):
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config', new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            authentication = BearerTokenAuthentication()
            response_mock = Mock(return_value=Mock(status_code=200,
                                                   json=Mock(return_value={}),
                                                   raise_for_status=Mock(return_value=None)))
            with patch('oidc_auth.authentication.requests.get', response_mock):
                result = authentication.get_userinfo(b'token')
                assert result == {}

    def test_get_user_info_endpoint_with_missing_field(self):
        self.openid_configuration.pop('userinfo_endpoint')
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config', new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            authentication = BearerTokenAuthentication()
            with self.assertRaisesMessage(AuthenticationFailed, 'userinfo_endpoint'):
                authentication.get_userinfo(b'faketoken')


class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), 'a')

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
        self.assertEqual(resp.status_code, 200)

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

    @patch('oidc_auth.authentication.jwt.decode')
    @patch('oidc_auth.authentication.logger')
    def test_decode_jwt_logs_exception_message_when_decode_throws_exception(
        self,
        logger_mock, decode
    ):
        auth = 'JWT ' + make_id_token(self.user.username)
        decode.side_effect = DecodeError, BadSignatureError

        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)

        self.assertEqual(resp.status_code, 401)
        logger_mock.exception.assert_called_once_with(
            'Invalid Authorization header. JWT Signature verification failed.')
