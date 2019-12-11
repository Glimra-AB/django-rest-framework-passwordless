import logging

from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import user_logged_in

from rest_framework import parsers, renderers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework.views import APIView

from drfpasswordless.models import RefreshToken, CallbackToken
from drfpasswordless.settings import api_settings
from drfpasswordless.serializers import (
    EmailAuthSerializer,
    MobileAuthSerializer,
    CallbackTokenAuthSerializer,
    RefreshTokenAuthSerializer,
    CallbackTokenVerificationSerializer,
    EmailVerificationSerializer,
    MobileVerificationSerializer,
)
from drfpasswordless.services import TokenService
from drfpasswordless.authentication import is_token_expired,token_expiration_time

logger = logging.getLogger(__name__)


class AbstractBaseObtainCallbackToken(APIView):
    """
    This returns a 6-digit callback token we can trade for a user's Auth Token and optionally a Refresh Token
    """
    success_response = "A login token has been sent to you."
    failure_response = "Unable to send you a login code. Try again later."

    message_payload = {}

    @property
    def serializer_class(self):
        # Our serializer depending on type
        raise NotImplementedError

    @property
    def alias_type(self):
        # Alias Type
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        # Only allow auth types allowed in settings.
        if self.alias_type.upper() not in api_settings.PASSWORDLESS_AUTH_TYPES:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(data=request.data, context={'request': request})
        # NOTE: this potentially CREATES a User with the given alias (email/phone) and other user-data (depending on the settings),
        # if create=true was given and the User doesn't exist already
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            # Create and send callback token
            # If devlink=true is provided during the request, we use a different link base for the callback link, to support dev-apps
            if 'devlink' in serializer.validated_data and serializer.validated_data['devlink']:
                linkbase = api_settings.PASSWORDLESS_DEV_LINK_BASE
            else:
                linkbase = api_settings.PASSWORDLESS_PROD_LINK_BASE

            if not user.is_active:  # in this case, mimic the user not being found at all (used for soft-deletion)
                return Response(status=status.HTTP_404_NOT_FOUND)

            if not user.is_demo:
                success = TokenService.send_token(user, self.alias_type, linkbase, **self.message_payload)
            else:
                success = False

            if success:
                status_code = status.HTTP_200_OK
                response_detail = self.success_response
            else:
                status_code = status.HTTP_400_BAD_REQUEST
                response_detail = self.failure_response
            return Response({'detail': response_detail}, status=status_code)
        else:
            return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)


class ObtainEmailCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = EmailAuthSerializer
    success_response = "A login token has been sent to your email."
    failure_response = "Unable to email you a login code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {'email_subject': email_subject,
                       'email_plaintext': email_plaintext,
                       'email_html': email_html}


class ObtainMobileCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = MobileAuthSerializer
    success_response = "We texted you a login code."
    failure_response = "Unable to send you a login code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class ObtainEmailVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailVerificationSerializer
    success_response = "A verification token has been sent to your email."
    failure_response = "Unable to email you a verification code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {
        'email_subject': email_subject,
        'email_plaintext': email_plaintext,
        'email_html': email_html
    }


class ObtainMobileVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = MobileVerificationSerializer
    success_response = "We texted you a verification code."
    failure_response = "Unable to send you a verification code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class AbstractBaseObtainAuthToken(APIView):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our 6 digit callback token and source, or from a refreshtoken
    """
    serializer_class = None

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        #print('blurk w serializer of class {} and refresh_token {}'.format(str(serializer.__class__), request.data['refresh_token']))
        # The serializer validate() looks up the user in the callback token or refreshtoken table, and writes it in 'user' if it exists
        # Note that we can get here with an incoming refreshtoken even if USE_REFRESH_TOKENS is disabled, however it won't match any
        # in the table.
        # TODO: we might want to send failed serializers to Sentry here preferably as some apps have had problems in this step. will cause
        # spam though if bots find this endpoint.
        if serializer.is_valid(raise_exception=True):
            by_refresh_token = 'refresh_token' in request.data   # normally we get here by 'token' or 'refresh_token'
            user = serializer.validated_data['user']

            if api_settings.PASSWORDLESS_REUSE_AUTH_TOKENS:
                access_token, created = Token.objects.get_or_create(user=user)
                # Make sure we don't dole out an expired token
                if is_token_expired(access_token):
                    access_token.delete()
                    access_token = Token.objects.create(user=user)
            else:
                # BROKEN for now, as the standard rest_framework.authtoken model has a onetoone correspondance with the user, so it can
                # only keep a single auth token per user.
                access_token = Token.objects.create(user=user)
                created = False
                # Don't immediately invalidate older auth tokens, as the user might have multiple clients. Note that if this option is
                # used, there should be another mechanism that times out the auth tokens or the table will just keep filling up.
                
            if api_settings.PASSWORDLESS_USE_REFRESH_TOKENS:
                if by_refresh_token:
                    # Default is to send out the same refresh token back to the client which it used to refresh.
                    # The serializer validation above will have checked that the refresh_token is still valid
                    refresh_token = serializer.validated_data['refresh_token']
                    if api_settings.PASSWORDLESS_ROTATE_REFRESH_TOKENS:
                        # Every time a refresh token is used, we create a new one and send back, keeping the expiration relative the last use
                        refresh_token.delete()
                        refresh_token = RefreshToken.objects.create(user=user)
                else:
                    # Incoming callback token, we should also return a fresh refresh token in this case if enabled
                    #
                    # Always create a new, so the user can login and logout on multiple devices independently
                    #
                    # (TODO: should add an endpoint to invalidate all refresh tokens for a user, hook into the logout path or something)
                    refresh_token = RefreshToken.objects.create(user=user)
            else:
                refresh_token = None
                
            # Consider this a login action for the user and update the user's last_login by sending a signal to django.contrib.auth
            # As the UserLogin log also receives this, include the by_refresh_token so we can log how the user logged in and
            # the client's position if given.
            user_logged_in.send(sender=type(user), request=request, user=user, by_refresh_token=by_refresh_token,
                                pos_lat=serializer.validated_data.get('pos_lat'), pos_long=serializer.validated_data.get('pos_long'))

            # At this point we expire the CallbackToken(s) since the user is logged in, to reduce the chance of a spam robot finding the
            # combination during the 15 minutes the token is potentially valid after this. If something breaks here, the client will have
            # to re-request a token. Never remove the demo-user's special login token.
            if not user.is_demo:
                CallbackToken.objects.filter(user=user).delete()
            
            # Return the access token to the client, optionally with a refresh token
            if refresh_token is None:
                return Response({ 'token': access_token.key, 'expiration': token_expiration_time(access_token) },
                                status=status.HTTP_200_OK)
            else:
                return Response({ 'token': access_token.key, 'expiration': token_expiration_time(access_token),
                                  'refresh_token': refresh_token.key.hex },
                                status=status.HTTP_200_OK)
        else:
            # Note: we will only get here if the is_valid does not throw an Exception (which it normally does for a malformed field)
            logger.error("Couldn't log in unknown user. Errors on serializer: {}".format(serializer.error_messages))
            
        return Response({'detail': 'Couldn\'t log you in. Try again later.'}, status=status.HTTP_400_BAD_REQUEST)


class ObtainAuthTokenFromCallbackToken(AbstractBaseObtainAuthToken):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our callback token and source.
    """
    permission_classes = (AllowAny,)
    serializer_class = CallbackTokenAuthSerializer

class ObtainAuthTokenFromRefreshToken(AbstractBaseObtainAuthToken):
    """
    This returns an Auth Token based on a refresh token
    """
    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenAuthSerializer

    
class VerifyAliasFromCallbackToken(APIView):
    """
    This verifies an alias on correct callback token entry using the same logic as auth.
    Should be refactored at some point.
    """
    serializer_class = CallbackTokenVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'user_id': self.request.user.id})
        if serializer.is_valid(raise_exception=True):
            return Response({'detail': 'Alias verified.'}, status=status.HTTP_200_OK)
        else:
            logger.error("Couldn't verify unknown user. Errors on serializer: {}".format(serializer.error_messages))

        return Response({'detail': 'We couldn\'t verify this alias. Try again later.'}, status.HTTP_400_BAD_REQUEST)
