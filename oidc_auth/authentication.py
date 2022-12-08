import logging
import time

from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import (BadSignatureError, DecodeError,
                                 ExpiredTokenError, JoseError)
from authlib.oidc.core.claims import IDToken
from django.utils.encoding import smart_str
from django.utils.translation import gettext as _
from requests import request
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache

logging.basicConfig()
logger = logging.getLogger(__name__)


def get_user_none(request, id_token):
    return None


class UserInfo(dict):
    """Wrapper class to allow checks to see if the object is a JWT token"""
    pass


class JWTToken(dict):
    """Wrapper class to allow checks to see if the object is a JWT token"""
    pass

class JSONWebTokenAuthentication(BaseAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    www_authenticate_realm = 'api'

    @property
    def claims_options(self):
        _claims_options = {
            'iss': {
                'essential': True,
                'values': [self.issuer]
            },
            'aud': {
                'essential': True,
                'values': [self.audience]
            }
        }
        return _claims_options

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        payload = self.decode_jwt(jwt_value)
        self.validate_claims(payload)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, payload)

        return user, JWTToken(payload)

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)

        return auth[1]

    def jwks(self):
        return JsonWebKey.import_key_set(self.jwks_data())

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        r = request("GET", api_settings.JWKS_ENDPOINT, allow_redirects=True)
        r.raise_for_status()
        return r.json()

    @property
    def issuer(self):
        return api_settings.ISSUER

    @property
    def audience(self):
        return api_settings.AUDIENCE


    def decode_jwt(self, jwt_value):
        try:
            id_token = jwt.decode(
                jwt_value.decode('ascii'),
                key=self.jwks(),
                claims_cls=IDToken,
                claims_options=self.claims_options
            )
        except (BadSignatureError, DecodeError):
            msg = _(
                'Invalid Authorization header. JWT Signature verification failed.')
            logger.exception(msg)
            raise AuthenticationFailed(msg)
        except AssertionError:
            msg = _(
                'Invalid Authorization header. Please provide base64 encoded ID Token'
            )
            raise AuthenticationFailed(msg)

        return id_token

    def validate_claims(self, id_token):
        try:
            id_token.validate(
                now=int(time.time()),
            )
        except ExpiredTokenError:
            msg = _('Invalid Authorization header. JWT has expired.')
            raise AuthenticationFailed(msg)
        except JoseError as e:
            msg = _(str(type(e)) + str(e))
            raise AuthenticationFailed(msg)

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
