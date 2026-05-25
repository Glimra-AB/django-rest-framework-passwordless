from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from drfpasswordless.models import CallbackToken, RefreshToken
from drfpasswordless.settings import DEFAULTS, api_settings


User = get_user_model()


class TokenExchangeAPITestCase(APITestCase):

    def setUp(self):
        self.reset_passwordless_settings()

    def tearDown(self):
        self.reset_passwordless_settings()

    def reset_passwordless_settings(self):
        for key, value in DEFAULTS.items():
            setattr(api_settings, key, value)
        if hasattr(mail, 'outbox'):
            mail.outbox = []

    def latest_callback_token(self, user):
        return CallbackToken.objects.filter(user=user, is_active=True).latest()

    def request_email_token(self, email, **data):
        payload = {'email': email}
        payload.update(data)
        return self.client.post('/auth/email/', payload)

    def request_mobile_token(self, mobile, **data):
        payload = {'mobile': mobile}
        payload.update(data)
        return self.client.post('/auth/mobile/', payload)

    def exchange_callback_token(self, callback_token):
        return self.client.post('/callback/auth/', {'token': callback_token.key})

    def enable_email_auth(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'

    def enable_mobile_auth(self):
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15550000000'


class CallbackTokenExchangeAPITests(TokenExchangeAPITestCase):

    def test_email_login_happy_flow_sends_email_and_consumes_callback_token(self):
        self.enable_email_auth()
        user = User.objects.create(email='happy@example.com')

        response = self.request_email_token(user.email)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'detail': 'A login token has been sent to your email.',
            'code': None,
        })
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [user.email])

        callback_token = self.latest_callback_token(user)
        self.assertTrue(any(
            callback_token.key in content
            for content, _ in mail.outbox[0].alternatives
        ))

        callback_response = self.exchange_callback_token(callback_token)

        self.assertEqual(callback_response.status_code, status.HTTP_200_OK)
        self.assertEqual(callback_response.data['token'], Token.objects.get(user=user).key)
        self.assertIn('expiration', callback_response.data)
        self.assertFalse(CallbackToken.objects.filter(user=user).exists())

    def test_mobile_login_happy_flow_returns_auth_token(self):
        self.enable_mobile_auth()
        user = User.objects.create(mobile='+15551234567')

        response = self.request_mobile_token(user.mobile)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'detail': 'We texted you a login code.',
            'code': None,
        })

        callback_response = self.exchange_callback_token(self.latest_callback_token(user))

        self.assertEqual(callback_response.status_code, status.HTTP_200_OK)
        self.assertEqual(callback_response.data['token'], Token.objects.get(user=user).key)
        self.assertIn('expiration', callback_response.data)

    def test_login_token_request_rejects_unknown_alias_without_create(self):
        self.enable_email_auth()

        response = self.request_email_token('missing@example.com')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 0)
        self.assertEqual(CallbackToken.objects.count(), 0)

    def test_login_token_request_rejects_disabled_user(self):
        self.enable_email_auth()
        user = User.objects.create(email='disabled@example.com', is_active=False)

        response = self.request_email_token(user.email)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(CallbackToken.objects.count(), 0)

    def test_callback_exchange_rejects_missing_token(self):
        response = self.client.post('/callback/auth/', {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('token', response.data)

    def test_callback_exchange_rejects_inactive_token(self):
        user = User.objects.create(email='inactive-token@example.com')
        callback_token = CallbackToken.objects.create(
            user=user,
            to_alias=user.email,
            to_alias_type='EMAIL',
            is_active=False,
        )

        response = self.exchange_callback_token(callback_token)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_callback_exchange_rejects_age_expired_token_and_marks_it_inactive(self):
        user = User.objects.create(email='expired@example.com')
        callback_token = CallbackToken.objects.create(
            user=user,
            to_alias=user.email,
            to_alias_type='EMAIL',
        )
        CallbackToken.objects.filter(pk=callback_token.pk).update(
            created_at=timezone.now() - timedelta(seconds=api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME + 1)
        )

        response = self.exchange_callback_token(callback_token)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        callback_token.refresh_from_db()
        self.assertEqual(callback_token.is_active, False)

    def test_verification_callback_rejects_token_owned_by_different_user(self):
        self.enable_email_auth()
        token_owner = User.objects.create(email='owner@example.com')
        other_user = User.objects.create(email='other@example.com')
        response = self.request_email_token(token_owner.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.client.force_authenticate(user=other_user)
        verification_response = self.client.post(
            '/callback/verify/',
            {'token': self.latest_callback_token(token_owner).key},
        )

        self.assertEqual(verification_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_callback_exchange_returns_refresh_token_when_enabled(self):
        self.enable_email_auth()
        api_settings.PASSWORDLESS_USE_REFRESH_TOKENS = True
        user = User.objects.create(email='refresh@example.com')
        response = self.request_email_token(user.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        callback_response = self.exchange_callback_token(self.latest_callback_token(user))

        self.assertEqual(callback_response.status_code, status.HTTP_200_OK)
        self.assertEqual(callback_response.data['token'], Token.objects.get(user=user).key)
        self.assertEqual(callback_response.data['refresh_token'], RefreshToken.objects.get(user=user).key.hex)


class RefreshTokenExchangeAPITests(TokenExchangeAPITestCase):

    def login_with_refresh_token_enabled(self, email):
        self.enable_email_auth()
        api_settings.PASSWORDLESS_USE_REFRESH_TOKENS = True
        user = User.objects.create(email=email)
        response = self.request_email_token(user.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        login_response = self.exchange_callback_token(self.latest_callback_token(user))
        return user, login_response

    def test_refresh_token_happy_flow_rotates_token(self):
        api_settings.PASSWORDLESS_ROTATE_REFRESH_TOKENS = True
        user, login_response = self.login_with_refresh_token_enabled('rotate@example.com')
        old_refresh_token = login_response.data['refresh_token']

        refresh_response = self.client.post('/refresh/auth/', {'refresh_token': old_refresh_token})

        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertEqual(refresh_response.data['token'], Token.objects.get(user=user).key)
        self.assertNotEqual(refresh_response.data['refresh_token'], old_refresh_token)
        self.assertFalse(RefreshToken.objects.filter(key=old_refresh_token).exists())
        self.assertTrue(RefreshToken.objects.filter(
            key=refresh_response.data['refresh_token'],
            user=user,
        ).exists())

    def test_refresh_token_rejects_old_token_after_rotation(self):
        api_settings.PASSWORDLESS_ROTATE_REFRESH_TOKENS = True
        user, login_response = self.login_with_refresh_token_enabled('old-refresh@example.com')
        old_refresh_token = login_response.data['refresh_token']
        refresh_response = self.client.post('/refresh/auth/', {'refresh_token': old_refresh_token})
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)

        second_refresh_response = self.client.post('/refresh/auth/', {'refresh_token': old_refresh_token})

        self.assertEqual(second_refresh_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_access_token_cannot_be_used_to_get_new_refresh_token(self):
        user, login_response = self.login_with_refresh_token_enabled('access-token-refresh@example.com')
        access_token = login_response.data['token']

        refresh_response = self.client.post('/refresh/auth/', {'refresh_token': access_token})

        self.assertEqual(refresh_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(RefreshToken.objects.filter(user=user).count(), 1)

    def test_refresh_token_rejected_when_refresh_tokens_disabled(self):
        user = User.objects.create(email='disabled-refresh@example.com')
        refresh_token = RefreshToken.objects.create(user=user)

        response = self.client.post('/refresh/auth/', {'refresh_token': refresh_token.key.hex})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_token_rejects_invalid_token(self):
        api_settings.PASSWORDLESS_USE_REFRESH_TOKENS = True

        response = self.client.post('/refresh/auth/', {'refresh_token': '0' * 32})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_token_rejects_expired_token_and_marks_it_inactive(self):
        api_settings.PASSWORDLESS_USE_REFRESH_TOKENS = True
        user = User.objects.create(email='expired-refresh@example.com')
        refresh_token = RefreshToken.objects.create(user=user)
        RefreshToken.objects.filter(pk=refresh_token.pk).update(
            created_at=timezone.now() - timedelta(seconds=api_settings.PASSWORDLESS_REFRESHTOKEN_EXPIRE_TIME + 1)
        )

        response = self.client.post('/refresh/auth/', {'refresh_token': refresh_token.key.hex})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        refresh_token.refresh_from_db()
        self.assertEqual(refresh_token.is_active, False)
