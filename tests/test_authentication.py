import sys
import logging
from django.http import HttpResponse
from django.test import TestCase
from django.urls import re_path as url
from oidc_auth.authentication import JSONWebTokenAuthentication, JWTToken
from oidc_auth.test import AuthenticationTestCaseMixin, make_id_token, make_local_token
from rest_framework.permissions import BasePermission
from rest_framework.views import APIView

if sys.version_info > (3,):
    long = int

logging.basicConfig()
logger = logging.getLogger(__name__)

class TokenPermission(BasePermission):
    """Checks if the token has correct permissions"""

    def has_permission(self, request, _view):
        token = request.auth  # type: JWTToken
        if not token:
            return False
        if not isinstance(token, JWTToken):
            return False
        return True

class MockView(APIView):
    permission_classes = (TokenPermission,)
    authentication_classes = (JSONWebTokenAuthentication,)

    def get(self, request):
        return HttpResponse('a')


urlpatterns = [
    url(r'^test/$', MockView.as_view(), name="testview")
]


class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200, resp.content.decode())
        self.assertEqual(resp.content.decode(), 'a')

    def test_using_valid_jwt_and_local_issuer(self):
        auth = 'JWT ' + make_local_token()
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
        auth = 'JWT ' + make_id_token(self.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_issuer(self):
        auth = 'JWT ' + \
               make_id_token(self.username, iss='http://something.com')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_audience(self):
        auth = 'JWT ' + make_id_token(self.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_too_new_jwt(self):
        auth = 'JWT ' + make_id_token(self.username, nbf=999999999999)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.username, aud=['you', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.username, aud=['we', 'me'])
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences_and_authorized_party(self):
        auth = 'JWT ' + \
               make_id_token(self.username, aud=['you', 'me'], azp='you')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_signature(self):
        auth = 'JWT ' + make_id_token(self.username)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401)

    def test_should_fail_without_aud_claim(self):
        auth = 'JWT ' + make_id_token(self.username, aud=None)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_should_fail_without_iss_claim(self):
        auth = 'JWT ' + make_id_token(self.username, iss=None)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_should_fail_without_exp_claim(self):
        auth = 'JWT ' + make_id_token(self.username, exp=None)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_should_fail_without_nbf_claim(self):
        auth = 'JWT ' + make_id_token(self.username, nbf=None)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_jwks_auth_should_fail_with_missing_kid(self):
        auth = 'JWT ' + make_id_token(self.username, include_kid=False)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_jwks_auth_should_fail_with_invalid_kid(self):
        auth = 'JWT ' + make_id_token(self.username, kid="fake_kid")
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_should_succeed_without_iat_kid(self):
        auth = 'JWT ' + make_id_token(self.username, iat=None)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
