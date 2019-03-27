from datetime import timedelta
from django.utils import timezone

from rest_framework.authentication import TokenAuthentication
from rest_framework import exceptions

from drfpasswordless.settings import api_settings

# This is an override of django rest frameworks TokenAuthentication class, replacing the authenticate_credentials function to
# check expiration time of the auth tokens

def is_token_expired(token):
    return (token.created < (timezone.now() - timedelta(seconds=api_settings.PASSWORDLESS_AUTHTOKEN_EXPIRE_TIME)))

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

