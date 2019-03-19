import logging
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.validators import RegexValidator
from django.utils import timezone
from rest_framework import serializers
from drfpasswordless.models import CallbackToken, RefreshToken
from drfpasswordless.settings import api_settings
from drfpasswordless.utils import verify_user_alias

logger = logging.getLogger(__name__)
UserModel = get_user_model()


class TokenField(serializers.CharField):
    default_error_messages = {
        'required': _('Invalid Token'),
        'invalid': _('Invalid Token'),
        'blank': _('Invalid Token'),
        'max_length': _('Tokens are {max_length} characters long.'),
        'min_length': _('Tokens are {min_length} characters long.')
    }


class AbstractBaseAliasAuthenticationSerializer(serializers.Serializer):
    """
    Abstract class that returns a callback token based on the field given
    Returns a token if valid, None or a message if not.
    """
    @property
    def alias_type(self):
        # The alias type, either email or mobile
        raise NotImplementedError

    def validate(self, attrs):
        alias = attrs.get(self.alias_type)

        if alias:
            # Create or authenticate a user and return it

            if api_settings.PASSWORDLESS_REGISTER_NEW_USERS is True:
                # If new aliases should register new users.
                user, created = UserModel.objects.get_or_create(**{self.alias_type: alias})
            else:
                # If new aliases should not register new users.
                try:
                    user = UserModel.objects.get(**{self.alias_type: alias})
                except UserModel.DoesNotExist:
                    user = None

            if user:
                if not user.is_active:
                    # If valid, return attrs so we can create a token in our logic controller
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)
            else:
                msg = _('No account is associated with this alias.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Missing %s.') % self.alias_type
            raise serializers.ValidationError(msg)

        attrs['user'] = user
        return attrs


class EmailAuthSerializer(AbstractBaseAliasAuthenticationSerializer):
    @property
    def alias_type(self):
        return 'email'

    email = serializers.EmailField()


class MobileAuthSerializer(AbstractBaseAliasAuthenticationSerializer):
    @property
    def alias_type(self):
        return 'mobile'

    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                 message="Mobile number must be entered in the format:"
                                         " '+999999999'. Up to 15 digits allowed.")
    mobile = serializers.CharField(validators=[phone_regex], max_length=15)


"""
Verification
"""


class AbstractBaseAliasVerificationSerializer(serializers.Serializer):
    """
    Abstract class that returns a callback token based on the field given
    Returns a token if valid, None or a message if not.
    """
    @property
    def alias_type(self):
        # The alias type, either email or mobile
        raise NotImplementedError

    def validate(self, attrs):

        msg = _('There was a problem with your request.')

        if self.alias_type:
            # Get request.user
            # Get their specified valid endpoint
            # Validate

            request = self.context["request"]
            if request and hasattr(request, "user"):
                user = request.user
                if user:
                    if not user.is_active:
                        # If valid, return attrs so we can create a token in our logic controller
                        msg = _('User account is disabled.')

                    else:
                        if hasattr(user, self.alias_type):
                            # Has the appropriate alias type
                            attrs['user'] = user
                            return attrs
                        else:
                            msg = _('This user doesn\'t have an %s.' % self.alias_type)
            raise serializers.ValidationError(msg)
        else:
            msg = _('Missing %s.') % self.alias_type
            raise serializers.ValidationError(msg)


class EmailVerificationSerializer(AbstractBaseAliasVerificationSerializer):
    @property
    def alias_type(self):
        return 'email'


class MobileVerificationSerializer(AbstractBaseAliasVerificationSerializer):
    @property
    def alias_type(self):
        return 'mobile'


"""
Callback Token
"""

def token_valid_for_login(token, expiry_time):
    """
    This validates the expiration time for both CallbackTokens and RefreshTokens
    (currently no other checks are needed, the token can only get here if it's is_active)
    """
    age_in_seconds = (timezone.now() - token.created_at).total_seconds()

    if age_in_seconds <= expiry_time:
            return True
    else:
        # Expired, so mark is_active false. It's not really necessary for invalidating the token as expiration time is always checked,
        # but it allows another token to be created with the same key at least. A cronjob should prune the expired tokens from the db.
        token.is_active = False
        token.save()
        return False

class AbstractBaseCallbackTokenSerializer(serializers.Serializer):
    """
    Abstract class inspired by DRF's own token serializer.
    Returns a user if valid, None or a message if not.
    """
    token = TokenField(min_length=6, max_length=6)


class CallbackTokenAuthSerializer(AbstractBaseCallbackTokenSerializer):

    def validate(self, attrs):
        try:
            # The key + is_active is unique so we can only get one result here
            token = CallbackToken.objects.get(key=attrs.get('token', None), is_active=True)

            if token and token_valid_for_login(token, api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME):
                user = token.user
                if user:
                    if not user.is_active:
                        msg = _('User account is disabled.')
                        raise serializers.ValidationError(msg)

                    if api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED \
                        or api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED:
                        # Mark this alias as verified
                        #user = UserModel.objects.get(pk=token.user.pk)
                        success = verify_user_alias(user, token)

                        if success is False:
                            msg = _('Error validating user alias.')
                            raise serializers.ValidationError(msg)

                    # Everything's good, return the validated user
                    attrs['user'] = user
                    return attrs

        except CallbackToken.DoesNotExist:
            logger.debug("drfpasswordless: tried to callback with non-existing callback token")
            pass
                
        # In all other cases, return an invalid error
        msg = _('Invalid Token')
        raise serializers.ValidationError(msg)

# This does the same, but looks for an active RefreshToken instead

class AbstractBaseRefreshTokenSerializer(serializers.Serializer):
    """
    Abstract class inspired by DRF's own token serializer.
    Returns a user if valid, None or a message if not.
    """
    refresh_token = TokenField(min_length=32, max_length=32)  # uuid4 is 128-bits, expressed as a hex here so 32 chars


class RefreshTokenAuthSerializer(AbstractBaseRefreshTokenSerializer):

    def validate(self, attrs):
        if api_settings.PASSWORDLESS_USE_REFRESH_TOKENS:
            try:
                refresh_token = RefreshToken.objects.get(key=attrs.get('refresh_token', None), is_active=True)
                if refresh_token and token_valid_for_login(refresh_token, api_settings.PASSWORDLESS_REFRESHTOKEN_EXPIRE_TIME):
                    user = refresh_token.user
                    if user:
                        if not user.is_active:
                            msg = _('User account is disabled.')
                            raise serializers.ValidationError(msg)
                        
                        # Everything's fine, give the user and validated refresh_token back to the caller through the attrs
                        attrs['user'] = user
                        attrs['refresh_token'] = refresh_token
                        return attrs

            except RefreshToken.DoesNotExist:
                logger.debug("drfpasswordless: Tried to get non-existing refresh token.")
                pass
                    
        # In all other cases, return the same "invalid" error msg
        msg = _('Invalid refreshtoken')
        raise serializers.ValidationError(msg)
        

class CallbackTokenVerificationSerializer(AbstractBaseCallbackTokenSerializer):
    """
    Takes a user and a token, verifies the token belongs to the user and
    validates the alias that the token was sent from.
    """

    def validate(self, attrs):
        try:
            user_id = self.context.get("user_id")
            callback_token = attrs.get('token', None)

            token = CallbackToken.objects.get(key=callback_token, is_active=True)
            user = UserModel.objects.get(pk=user_id)

            if token.user == user:
                # Check that the token.user is the request.user

                # Mark this alias as verified
                success = verify_user_alias(user, token)
                if success is False:
                    logger.debug("drfpasswordless: Error verifying alias.")

                attrs['user'] = user
                return attrs
            else:
                msg = _('This token is invalid. Try again later.')
                logger.debug("drfpasswordless: User token mismatch when verifying alias.")

        except CallbackToken.DoesNotExist:
            msg = _('Missing authentication token.')
            logger.debug("drfpasswordless: Tried to validate alias with bad token.")
            pass
        except User.DoesNotExist:
            msg = _('Missing user.')
            logger.debug("drfpasswordless: Tried to validate alias with bad user.")
            pass
        except PermissionDenied:
            msg = _('Insufficient permissions.')
            logger.debug("drfpasswordless: Permission denied while validating alias.")
            pass

        raise serializers.ValidationError(msg)
