import logging
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.validators import RegexValidator
from django.utils import timezone
from rest_framework import serializers
from drfpasswordless.models import CallbackToken, RefreshToken
from drfpasswordless.settings import api_settings
from drfpasswordless.utils import verify_user_alias
from django.db.utils import IntegrityError

from glimra.base.fields import PhoneNumberSerializerField

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
    As a side-effect, a User is created if not already existing with the given alias and other white-listed creation arguments
    If the alias matches an existing user, it cannot be updated currently even if it's not verified yet. TODO figure out what is
    best (probably allow updating the user as long as the user is not verified, after that it has to be locked obviously)
    """

    # We want to allow all national chars in the first/last names, but avoid HTML-style stuff etc. that could be
    # a security concern. TODO evaluate and check what works best.
    # \w matches alphanumerics and _, also add - and space to support Bengt-Ove etc. 
    name_regex = RegexValidator(regex=r'^[ \w-]+$')

    # These can optionally be passed when creating a new user. If passed, they have to be set to something at least.
    first_name = serializers.CharField(validators=[name_regex], min_length=1, max_length=30, required=False)
    last_name = serializers.CharField(validators=[name_regex], min_length=1, max_length=30, required=False)
    tos_version_accepted = serializers.IntegerField(min_value=1, required=False)

    # True if we request user creation (enforces require on some other fields than if we just request a callback link)
    create = serializers.BooleanField(required=False)

    # True if we request the callback link using the dev link format (sent by dev apps)
    devlink = serializers.BooleanField(required=False)

    # True if we request the callback link to just send a code and not a clickable link (used for desktop web logins)
    desktop = serializers.BooleanField(required=False)

    # The country of which the user belongs to
    country = serializers.CharField(required=False)

    @property
    def alias_type(self):
        # The alias type, either email or mobile
        raise NotImplementedError

    # Note: the ValidationError exceptions raised below, are caught and aggregated by DRF, so the is_valid() caller
    # doesn't see them as exceptions
    
    def validate(self, attrs):
        # We know this is there as it's marked required in the serializer field (email or mobile) below
        alias = attrs.get(self.alias_type)
        
        # Since phone number / email are unique by country
        # Default to Sweden for compatability
        country = attrs.get('country', 'se')

        if alias:
            # Create or authenticate a user and return it. The client has to explicitly request creation by 'create',
            # and if so, we require a specific set of fields. Otherwise, it's enough to just supply the alias field.
            if api_settings.PASSWORDLESS_REGISTER_NEW_USERS and attrs.get('create', False):
                # If new aliases should register new users.
                # We can optionally allow registration of more user model fields at the same time, these are
                # whitelisted in the settings variable and filtered here before passed to get_or_create

                if country == 'se':
                    default_digilets = api_settings.PASSWORDLESS_SE_NEW_USER_DIGILETS 
                else:
                    default_digilets = api_settings.PASSWORDLESS_FI_NEW_USER_DIGILETS 

                new_user_attrs = { self.alias_type: alias, 'country': country, 'digilets': default_digilets }

                for fkey in api_settings.PASSWORDLESS_USER_CREATION_FIELDS:
                    val = attrs.get(fkey, None)
                    if val is not None:
                        new_user_attrs[fkey] = val
                for reqkey in api_settings.PASSWORDLESS_USER_CREATION_FIELDS_REQ:
                    if not reqkey in new_user_attrs:
                        raise serializers.ValidationError('Field %s missing while creating new user' % reqkey)
                # The get_or_create is to make the register API call idempotent, so if it's repeated, you get the same result.
                # If we use only create here, the first call would create the user and the second call would return the validationerror.
                #
                # We get db integrity exceptions if we try to create a new user with the same email and/or mobile, even if
                # the other fields are different, which is good.
                try:
                    user, created = UserModel.objects.get_or_create(**new_user_attrs)
                except IntegrityError:
                    raise serializers.ValidationError('User email or mobile already taken')
            else:
                # If new aliases should not register new users but just "login" (send a new callback token)
                try:
                    # TODO: allow updating the user with the new attrs at this point, if the user is not validated on either of the
                    # email or phone yet but is still existing in the database.
                    user = UserModel.objects.get(**{self.alias_type: alias, 'country': country})
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

    # The email field is obviously required, but the mobile can be optional (and viceversa in the MobileAuthSerializer)
    # Note that if create=true is set (requesting user creation) then we do require all fields.
    email = serializers.EmailField(required=True)
    mobile = PhoneNumberSerializerField(required=False)


class MobileAuthSerializer(AbstractBaseAliasAuthenticationSerializer):
    @property
    def alias_type(self):
        return 'mobile'

    # See above
    email = serializers.EmailField(required=False)
    mobile = PhoneNumberSerializerField(required=True)

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

    if token.key == '999999': # this can't be generated by ourselves, it's a read-only demo-user magic link if it exist in the db
        # skip expiration check in this case
        print('DEMO USER CALLBACK TOKEN VALIDATED')
        return True
    
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

    pos_lat = serializers.DecimalField(max_digits=15, decimal_places=12, required=False)
    pos_long = serializers.DecimalField(max_digits=15, decimal_places=12, required=False)

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

    pos_lat = serializers.DecimalField(max_digits=15, decimal_places=12, required=False)
    pos_long = serializers.DecimalField(max_digits=15, decimal_places=12, required=False)
    
    def validate(self, attrs):
        if api_settings.PASSWORDLESS_USE_REFRESH_TOKENS:
            try:
                refresh_token = RefreshToken.objects.get(key=attrs.get('refresh_token', None), is_active=True)
                if refresh_token and token_valid_for_login(refresh_token, api_settings.PASSWORDLESS_REFRESHTOKEN_EXPIRE_TIME):
                    user = refresh_token.user
                    if user:
                        # TODO: should we require a secondary piece of information in addition to the refresh_token? The correct email or phone?
                        if not user.is_active:
                            msg = _('User account is disabled.')
                            raise serializers.ValidationError(msg)
                        
                        # Everything's fine, give the user a validated refresh_token back to the caller through the attrs
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
