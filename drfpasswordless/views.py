import logging

from django.utils import timezone
from django.contrib.auth import user_logged_in

from rest_framework import parsers, renderers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework.views import APIView

from drfpasswordless.models import RefreshToken
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
        # NOTE: this CREATES a User with the given alias (email/phone) and other user-data (depending on the settings), if it doesn't exist
        if serializer.is_valid(raise_exception=True):
            # Validate -
            user = serializer.validated_data['user']
            # Create and send callback token
            success = TokenService.send_token(user, self.alias_type, **self.message_payload)

            # Respond With Success Or Failure of Sent
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
        if serializer.is_valid(raise_exception=True):
            by_refresh_token = 'refresh_token' in request.data   # normally we get here by 'token' or 'refresh_token'
            user = serializer.validated_data['user']

            if api_settings.PASSWORDLESS_REUSE_AUTH_TOKENS:
                access_token, created = Token.objects.get_or_create(user=user)
            else:
                # BROKEN for now, as the standard rest_framework.authtoken model has a onetoone correspondance with the user, so it can
                # only keep a single auth token per user.
                access_token = Token.objects.create(user=user)
                created = False
                # Don't immediately invalidate older auth tokens, as the user might have multiple clients. Note that if this option is
                # used, there should be another mechanism that times out the auth tokens or the table will just keep filling up.
                
            if api_settings.PASSWORDLESS_USE_REFRESH_TOKENS:
                if by_refresh_token:
                    # Send out the same refresh token back to the client which it used to refresh.
                    refresh_token = serializer.validated_data['refresh_token']
                else:
                    # Incoming callback token, we should also return a fresh refresh token in this case if enabled
                    #
                    # Always create a new, so the user can login and logout on multiple devices independently
                    #
                    # (TODO: should be an endpoint to invalidate all refresh tokens for a user, hook into the logout path or something)
                    refresh_token = RefreshToken.objects.create(user=user)
            else:
                refresh_token = None
                
            # I'm not sure what this was supposed to achieve, disabled. But verify that new users can't login by an empty pw or so..
        
            #if created:
            #    # Initially set an unusable password if a user is created through this.
            #    user.set_unusable_password()
            #    user.save()

            # Consider this a login action for the user and update the user's last_login by sending a signal to django.contrib.auth
            user_logged_in.send(sender=type(user), request=request, user=user)
            
            if access_token:
                # Return the access token to the client, optionally with a refresh token
                if refresh_token is None:
                    return Response({ 'token': access_token.key }, status=status.HTTP_200_OK)
                else:
                    return Response({ 'token': access_token.key, 'refresh_token': refresh_token.key.hex }, status=status.HTTP_200_OK)
        else:
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
