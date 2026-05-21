from django.urls import re_path
from rest_framework.urlpatterns import format_suffix_patterns
from drfpasswordless.views import (ObtainEmailCallbackToken,
                                   ObtainMobileCallbackToken,
                                   ObtainAuthTokenFromCallbackToken,
                                   VerifyAliasFromCallbackToken,
                                   ObtainEmailVerificationCallbackToken,
                                   ObtainMobileVerificationCallbackToken, )

urlpatterns = [re_path(r'^callback/auth/$', ObtainAuthTokenFromCallbackToken.as_view(), name='auth_callback'),
               re_path(r'^auth/email/$', ObtainEmailCallbackToken.as_view(), name='auth_email'),
               re_path(r'^auth/mobile/$', ObtainMobileCallbackToken.as_view(), name='auth_mobile'),
               re_path(r'^callback/verify/$', VerifyAliasFromCallbackToken.as_view(), name='verify_callback'),
               re_path(r'^verify/email/$', ObtainEmailVerificationCallbackToken.as_view(), name='verify_email'),
               re_path(r'^verify/mobile/$', ObtainMobileVerificationCallbackToken.as_view(), name='verify_mobile')]

format_suffix_patterns(urlpatterns)
