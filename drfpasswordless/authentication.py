from datetime import timedelta
from django.utils import timezone

from rest_framework.authentication import TokenAuthentication
from rest_framework import exceptions


# This is an override of django rest frameworks TokenAuthentication class, replacing the authenticate_credentials function to
# check expiration time of the auth tokens

class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted')
                                                    
        if token.created < timezone.now() - timedelta(hours=1):  # TODO: set 24 hours when the refresh is well tested in all clients
            # TODO: possibly reinstate when this works fine. This is not strictly necessary though, only one Token per User and it is inactive now anyway
            #token.delete()
            raise exceptions.AuthenticationFailed('Token has expired')

        return token.user, token

