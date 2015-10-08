from calendar import timegm
import datetime
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_text
from django.utils.functional import cached_property
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS
import requests
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
import six
from .util import cache
from .settings import api_settings
from django.utils.translation import ugettext as _


def get_user_by_id(id_token):
    User = get_user_model()
    try:
        user = User.objects.get_by_natural_key(id_token.get('sub'))
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user


class JSONWebTokenAuthentication(BaseAuthentication):
    """ Token based authentication using the JSON Web Token standard
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        payload = self.decode_jwt(jwt_value)
        self.validate_claims(payload)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(payload)

        return user, payload

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)

        return auth[1]

    @cached_property
    def oidc_config(self):
        return requests.get(api_settings.OIDC_ENDPOINT + '/.well-known/openid-configuration').json()

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks(self):
        keys = KEYS()
        keys.load_from_url(self.oidc_config['jwks_uri'])
        return keys

    @cached_property
    def issuer(self):
        return self.oidc_config['issuer']

    def decode_jwt(self, jwt_value):
        keys = self.jwks()
        try:
            id_token = JWS().verify_compact(jwt_value, keys=keys)
        except JWKESTException:
            msg = _('Invalid Authorization header. JWT Signature verification failed.')
            raise AuthenticationFailed(msg)

        return id_token

    def validate_claims(self, id_token):
        if isinstance(id_token.get('aud'), six.string_types):
            # Support for multiple audiences
            id_token['aud'] = [id_token['aud']]

        if id_token.get('iss') != self.issuer:
            msg = _('Invalid Authorization header. Invalid JWT issuer.')
            raise AuthenticationFailed(msg)
        if not any(aud in api_settings.OIDC_AUDIENCES for aud in id_token.get('aud', [])):
            msg = _('Invalid Authorization header. Invalid JWT audience.')
            raise AuthenticationFailed(msg)
        if len(id_token['aud']) > 1 and 'azp' not in id_token:
            msg = _('Invalid Authorization header. Missing JWT authorized party.')
            raise AuthenticationFailed(msg)
        if 'azp' in id_token and id_token['azp'] not in api_settings.OIDC_AUDIENCES:
            msg = _('Invalid Authorization header. Invalid JWT authorized party.')
            raise AuthenticationFailed(msg)

        utc_timestamp = timegm(datetime.datetime.utcnow().utctimetuple())
        if utc_timestamp > id_token.get('exp', 0):
            msg = _('Invalid Authorization header. JWT has expired.')
            raise AuthenticationFailed(msg)
        if 'nbf' in id_token and utc_timestamp < id_token['nbf']:
            msg = _('Invalid Authorization header. JWT not yet valid.')
            raise AuthenticationFailed(msg)
        if utc_timestamp > id_token.get('iat', 0) + api_settings.OIDC_LEEWAY:
            msg = _('Invalid Authorization header. JWT too old.')
            raise AuthenticationFailed(msg)

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
