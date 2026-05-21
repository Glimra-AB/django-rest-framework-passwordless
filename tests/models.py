from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.core.validators import RegexValidator
from django.db import models

phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                             message="Mobile number must be entered in the format:"
                                     " '+999999999'. Up to 15 digits allowed.")


class CustomUser(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True, blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    mobile = models.CharField(validators=[phone_regex], max_length=15, unique=True, blank=True, null=True)
    mobile_verified = models.BooleanField(default=False)
    country = models.CharField(default='se', max_length=2)
    digilets = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    is_demo = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_washotron = models.BooleanField(default=False)
    is_pos = models.BooleanField(default=False)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    def can_login_with_mobile(self):
        if self.mobile:
            return True, None
        return False, 'missing_mobile'

    def send_action(self, alias_type, send_action, token, **message_payload):
        if send_action is None:
            return False, 'sending_error'

        return send_action(self, token, **message_payload), None

    def __str__(self):
        return self.email or self.mobile or str(self.pk)

    class Meta:
        app_label = 'tests'
