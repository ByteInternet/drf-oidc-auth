import logging
import time

import requests
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import (BadSignatureError, DecodeError,
                                 ExpiredTokenError, JoseError)
from authlib.oidc.core.claims import IDToken
from authlib.oidc.discovery import get_well_known_url
import jwt as pyjwt
from django.utils.encoding import smart_str
from django.utils.translation import gettext as _
from requests import request
from requests.exceptions import HTTPError
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache

logger = logging.getLogger(__name__)

jwt = JsonWebToken(['RS256', 'RS384', 'RS512'])

def get_user_none(request, id_token):
    return None

class UserInfo(dict):
    """Wrapper class to allow checks to see if the object is a JWT token"""
    pass

class BearerTokenAuthentication(BaseAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        bearer_token = self.get_bearer_token(request)
        if bearer_token is None:
            return None

        try:
            userinfo = self.get_userinfo(bearer_token)
        except HTTPError:
            msg = _('Invalid Authorization header. Unable to verify bearer token')
            raise AuthenticationFailed(msg)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, userinfo)

        return user, UserInfo(userinfo)

    def get_bearer_token(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.BEARER_AUTH_HEADER_PREFIX.lower()
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

    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def get_userinfo(self, token):
        userinfo_endpoint = api_settings.USERINFO_ENDPOINT
        if not userinfo_endpoint:
            raise AuthenticationFailed(_('Invalid userinfo_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.USERINFO_ENDPOINT.'))

        response = requests.get(userinfo_endpoint, headers={
            'Authorization': 'Bearer {0}'.format(token.decode('ascii'))})
        response.raise_for_status()

        return response.json()


class JWTToken(dict):
    """Wrapper class to allow checks to see if the object is a JWT token"""
    pass

class JSONWebTokenAuthentication(BaseAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    www_authenticate_realm = 'api'

    def claims_options(self, issuer):
        _claims_options = {
            'iss': {
                'essential': True,
                'values': [issuer]
            },
            'nbf': {
                'essential': True,
            },
        }
        issuer_config = self.get_issuer_config(issuer)
        issuer_options = issuer_config['OIDC_CLAIMS_OPTIONS']
        for key, value in issuer_options.items():
            _claims_options[key] = value
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

    def jwks(self, jwks_uri):
        return JsonWebKey.import_key_set(self.jwks_data(jwks_uri))

    @cache(ttl=api_settings.JWKS_EXPIRATION_TIME)
    def jwks_data(self, jwks_uri):
        r = request("GET", jwks_uri, allow_redirects=True)
        r.raise_for_status()
        return r.json()

    def decode_jwt(self, jwt_value):
        try:
            issuer = self.get_issuer_from_raw_token(jwt_value)
            key = self.get_key_for_issuer(issuer)
            id_token = jwt.decode(
                jwt_value.decode('ascii'),
                key,
                claims_cls=IDToken,
                claims_options=self.claims_options(issuer)
            )
        except (BadSignatureError, DecodeError, pyjwt.exceptions.DecodeError):
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

    def get_key_for_issuer(self, issuer):
        issuer_config = self.get_issuer_config(issuer)
        key = issuer_config['key']
        key_type = issuer_config['type']
        if key_type not in ['JWKS', 'PEM']:
            raise ValueError(f"{key_type} is not a valid type")
        if key_type == 'JWKS':
            key = self.jwks(key)
        elif key_type == 'PEM':
            key = bytes(key, encoding='utf-8')
        return key

    def get_issuer_from_raw_token(self, token):
        claims = self.get_claims_without_validation(token)
        if 'iss' not in claims:
            raise AuthenticationFailed("Token is missing the 'iss' claim")
        return claims['iss']

    def get_claims_without_validation(self, token):
        """Raises pyjwt.exceptions.DecodeError if token could not be decoded"""
        return pyjwt.decode(token, options={"verify_signature": False})

    def get_issuer_config(self, target_issuer):
        issuer = api_settings.JWT_ISSUERS.get(target_issuer)
        if not issuer:
            raise AuthenticationFailed("Invalid 'iss' claim")
        return issuer

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
