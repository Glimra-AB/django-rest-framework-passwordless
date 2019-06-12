from django.urls import path
from drfpasswordless.views import (
     ObtainEmailCallbackToken,
     ObtainMobileCallbackToken,
     ObtainAuthTokenFromCallbackToken,
     ObtainAuthTokenFromRefreshToken,
     VerifyAliasFromCallbackToken,
     ObtainEmailVerificationCallbackToken,
     ObtainMobileVerificationCallbackToken,
)

urlpatterns = [
     path('callback/auth/', ObtainAuthTokenFromCallbackToken.as_view(), name='auth_callback'),
     path('refresh/auth/', ObtainAuthTokenFromRefreshToken.as_view(), name='auth_refresh'),
     path('auth/email/', ObtainEmailCallbackToken.as_view(), name='auth_email'),
     path('auth/mobile/', ObtainMobileCallbackToken.as_view(), name='auth_mobile'),
# Removed as we don't use these. But I guess the paths we actually use should just be copied and redone elsewhere
#     path('callback/verify/', VerifyAliasFromCallbackToken.as_view(), name='verify_callback'),
#     path('verify/email/', ObtainEmailVerificationCallbackToken.as_view(), name='verify_email'),
#     path('verify/mobile/', ObtainMobileVerificationCallbackToken.as_view(), name='verify_mobile'),
]
