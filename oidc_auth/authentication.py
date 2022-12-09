import logging
import time

from authlib.jose import JsonWebToken
from authlib.jose.errors import (BadSignatureError, DecodeError,
                                 ExpiredTokenError, JoseError)
from authlib.oidc.core.claims import IDToken
import jwt as pyjwt
from django.utils.encoding import smart_str
from django.utils.translation import gettext as _
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .decode_key import PEMDecodeKey, JWKSDecodeKey

logger = logging.getLogger(__name__)

jwt = JsonWebToken(['RS256', 'RS512'])

def get_user_none(request, id_token):
    """Default function for mapping token to user. Returns None"""
    return None

class JWTToken(dict):
    """Wrapper class to allow checks to see if the object is a JWT token"""
    pass

class JSONWebTokenAuthentication(BaseAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    www_authenticate_realm = 'api'
    ISSUER_TYPES = {
        'JWKS': JWKSDecodeKey,
        'PEM': PEMDecodeKey,
    }

    def claims_options(self, issuer):
        _claims_options = {
            'iss': {
                'essential': True,
                'values': [issuer]
            },
            'aud': {
                'essential': True,
                'values': self.audiences
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

    @property
    def audiences(self):
        return api_settings.AUDIENCES

    def get_issuer_from_raw_token(self, token):
        claims = pyjwt.decode(token, options={"verify_signature": False})
        if 'iss' not in claims:
            raise AuthenticationFailed("Token is missing 'iss' claim")
        return claims['iss']

    def get_key_for_issuer(self, target_issuer):
        issuer = api_settings.ISSUERS.get(target_issuer)
        if not issuer:
            raise AuthenticationFailed("Invalid 'iss' claim")
        type = issuer['type']
        key_class = self.ISSUER_TYPES[type]
        key = key_class(issuer['key'])
        return key.key

    def decode_jwt(self, jwt_value):
        try:
            issuer = self.get_issuer_from_raw_token(jwt_value)
            key = self.get_key_for_issuer(issuer)
            id_token = jwt.decode(
                jwt_value.decode('ascii'),
                key=key,
                claims_cls=IDToken,
                claims_options=self.claims_options(issuer)
            )
        except (BadSignatureError, DecodeError, pyjwt.exceptions.DecodeError):
            msg = _(
                'Invalid Authorization header. JWT Signature verification failed.')
            logger.exception(msg)
            raise AuthenticationFailed(msg)
        except (AssertionError):
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
