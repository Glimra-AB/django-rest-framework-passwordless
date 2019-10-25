from datetime import timedelta
from django.utils import timezone

from rest_framework.authentication import TokenAuthentication
from rest_framework import serializers,exceptions
from rest_auth.models import TokenModel

from drfpasswordless.settings import api_settings

# This is an override of django rest frameworks TokenAuthentication class, replacing the authenticate_credentials function to
# check expiration time of the auth tokens

def is_token_expired(token):
    return (token.created < (timezone.now() - timedelta(seconds=api_settings.PASSWORDLESS_AUTHTOKEN_EXPIRE_TIME)))

def token_expiration_time(token):
    return (token.created + timedelta(seconds=api_settings.PASSWORDLESS_AUTHTOKEN_EXPIRE_TIME))

# Used by django-rest-auth during /login, we need to hook it to check if the token it tries to give the user has in fact expired
# Set it up by pointing REST_AUTH_TOKEN_CREATOR to this function in settings.py

def expiring_create_token(token_model, user, serializer):
    token, _ = token_model.objects.get_or_create(user=user)
    # Make sure we don't dole out an expired token
    if is_token_expired(token):
        # TODO: this can race it seems, the delete not being ready when the .create below is run (seems improbable though...)
        token.delete()
        token = token_model.objects.create(user=user)
    return token

class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted')
                                                    
        if is_token_expired(token):
            # The Token should not really need to be deleted here, but we are missing an override for django-rest-auth's LoginView
            # handling, where it performs get_or_create per default and that will deal out the expired token giving the user no
            # possibility to flush the expired token in that case.
            # TODO: should fix LoginView in addition, at least that saves the user from actually having to try the API key to flush the
            # token which shouldn't be necessary.
            token.delete()
            raise exceptions.AuthenticationFailed('Token has expired')

        return token.user, token

class ExpiringTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for Token model. Adds the expiration time compared to the default rest-auth serializer.
    """

    expiration = serializers.SerializerMethodField()  
    
    class Meta:
        model = TokenModel
        fields = ('key','expiration',)

    def get_expiration(self, obj):
        return token_expiration_time(obj)

    
