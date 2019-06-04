import logging
from django.contrib.auth import get_user_model
from django.dispatch import receiver
from django.db.models import signals
from drfpasswordless.models import CallbackToken, RefreshToken
from drfpasswordless.models import generate_numeric_token
from drfpasswordless.settings import api_settings
from drfpasswordless.services import TokenService

logger = logging.getLogger(__name__)
            
@receiver(signals.pre_save, sender=CallbackToken)
def check_unique_tokens(sender, instance, **kwargs):
    """
    Ensures that mobile and email tokens are unique by redoing the key generation
    """
    if isinstance(instance, CallbackToken):
        while CallbackToken.objects.filter(key=instance.key, is_active=True).exists():
            instance.key = generate_numeric_token()


# Note: RefreshToken doesn't have a similar check, as the uuid generation should not collide and we allow several
# active refreshtokens for the same user (could be logged in through more than one device)
            
UserModel = get_user_model()

# Note: these verification sends use the production linkbase and since we don't store the dev/prod app status, we don't know
# what linkbase to use here. TODO

@receiver(signals.pre_save, sender=UserModel)
def update_alias_verification(sender, instance, **kwargs):
    """
    Flags a user's email as unverified if they change it.
    Optionally sends a verification token to the new endpoint.
    """
    if isinstance(instance, UserModel):

        if instance.id:

            if api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED is True:
                """
                For marking email aliases as not verified when a user changes it.
                """
                email_field = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
                email_verified_field = api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME

                # Verify that this is an existing instance and not a new one.
                try:
                    user_old = UserModel.objects.get(id=instance.id)  # Pre-save object
                    instance_email = getattr(instance, email_field)  # Incoming Email
                    old_email = getattr(user_old, email_field)  # Pre-save object email

                    if instance_email != old_email and instance_email != "" and instance_email is not None:
                        # Email changed, verification should be flagged
                        setattr(instance, email_verified_field, False)
                        if api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN is True:
                            email_subject = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT
                            email_plaintext = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE
                            email_html = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME
                            message_payload = {'email_subject': email_subject,
                                               'email_plaintext': email_plaintext,
                                               'email_html': email_html}
                            success = TokenService.send_token(instance, 'email', api_settings.PASSWORDLESS_PROD_LINK_BASE, **message_payload)

                            if success:
                                logger.info('drfpasswordless: Successfully sent email on updated address: %s'
                                            % instance_email)
                            else:
                                logger.info('drfpasswordless: Failed to send email to updated address: %s'
                                            % instance_email)

                except UserModel.DoesNotExist:
                    # User probably is just initially being created
                    setattr(instance, email_verified_field, True)

            if api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED is True:
                """
                For marking mobile aliases as not verified when a user changes it.
                """
                mobile_field = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
                mobile_verified_field = api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME

                # Verify that this is an existing instance and not a new one.
                try:
                    user_old = UserModel.objects.get(id=instance.id)  # Pre-save object
                    instance_mobile = getattr(instance, mobile_field)  # Incoming mobile
                    old_mobile = getattr(user_old, mobile_field)  # Pre-save object mobile

                    if instance_mobile != old_mobile and instance_mobile != "" and instance_mobile is not None:
                        # Mobile changed, verification should be flagged
                        setattr(instance, mobile_verified_field, False)
                        if api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN is True:
                            mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
                            message_payload = {'mobile_message': mobile_message}
                            success = TokenService.send_token(instance, 'mobile', api_settings.PASSWORDLESS_PROD_LINK_BASE, **message_payload)

                            if success:
                                logger.info('drfpasswordless: Successfully sent SMS on updated mobile: %s'
                                            % instance_mobile)
                            else:
                                logger.info('drfpasswordless: Failed to send SMS to updated mobile: %s'
                                            % instance_mobile)

                except UserModel.DoesNotExist:
                    # User probably is just initially being created
                    setattr(instance, mobile_verified_field, True)
