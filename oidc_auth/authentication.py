import logging

import jwt
from jwt import PyJWKClient
from django.utils.encoding import smart_str
from django.utils.translation import gettext as _
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .decode_key import PEMDecodeKey, JWKSDecodeKey

logger = logging.getLogger(__name__)

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
    REQUIRED_CLAIMS = ["exp", "nbf", "aud", "iss"]
    SUPPORTED_ALGORITHMS = ["RS256", "RS384", "RS512"]

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        payload = self.decode_pyjwt(jwt_value)

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

    def get_issuer_from_raw_token(self, token):
        claims = self.get_claims_without_validation(token)
        if 'iss' not in claims:
            raise AuthenticationFailed("Token is missing the 'iss' claim")
        return claims['iss']

    def get_claims_without_validation(self, token):
        """Raises pyjwt.exceptions.DecodeError if token could not be decoded"""
        return jwt.decode(token, options={"verify_signature": False})

    def get_issuer_config(self, target_issuer):
        issuer = api_settings.ISSUERS.get(target_issuer)
        if not issuer:
            raise AuthenticationFailed("Invalid 'iss' claim")
        return issuer

    def get_key_for_issuer(self, token, target_issuer):
        issuer = self.get_issuer_config(target_issuer)
        type = issuer['type']
        if type == "JWKS":
            jwks_client = PyJWKClient(issuer['key'])
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            key = signing_key.key
            raise AuthenticationFailed("GGOT TO END OF JWKS PATH")
        else:
            key = issuer['key']
        return key
        #key_class = self.ISSUER_TYPES[type]
        #key = key_class(token, issuer['key'])
        #return key.key

    def get_allowed_aud_for_issuer(self, target_issuer):
        issuer = self.get_issuer_config(target_issuer)
        return issuer['aud']

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)

    def decode_pyjwt(self, jwt_value):
        """Validates a raw token and returns a decoded token if validation is successful"""
        try:
            issuer = self.get_issuer_from_raw_token(jwt_value)
            key = self.get_key_for_issuer(jwt_value, issuer)
            audience = self.get_allowed_aud_for_issuer(issuer)
            logger.error(f"Key: {key}")
            validated_token = jwt.decode(
                jwt=jwt_value,
                algorithms=self.SUPPORTED_ALGORITHMS,
                key=key,
                options={
                    "require": self.REQUIRED_CLAIMS,
                    'verify_iat': False,
                },
                audience=audience,
                issuer=issuer,
            )
            return validated_token
        except jwt.exceptions.DecodeError as e:
            raise AuthenticationFailed("Error decoding token: invalid format")
        except jwt.exceptions.PyJWTError as e:
            logger.error(e)
            logger.error(type(e))
            raise AuthenticationFailed(f"Error validating token: {e}")
