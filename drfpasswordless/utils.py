import logging
import os
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.core.cache import cache
from django.db import transaction
from django.template import loader, Template, Context
from django.utils import timezone
from drfpasswordless.models import CallbackToken
from drfpasswordless.settings import api_settings

from sentry_sdk import add_breadcrumb

logger = logging.getLogger(__name__)
User = get_user_model()


# Helper called from the TokenService, create and return a token of the desired type while invalidating any previous tokens

def create_callback_token_for_user(user, token_type):

    token = None
    token_type = token_type.upper()

    # First deactivate all existing tokens for the User
    # TODO: option to delete them directly instead?
    with transaction.atomic():
        active_tokens = CallbackToken.objects.select_for_update().filter(user=user, is_active=True)
        active_tokens.update(is_active=False)
    
    if token_type == 'EMAIL':
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME))
    elif token_type == 'MOBILE':
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME))

    if token is not None:
        return token

    return None


def verify_user_alias(user, token):
    """
    Marks a user's contact point as verified depending on accepted token type.
    """
    if token.to_alias_type == 'EMAIL':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME) and \
           not getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, True)
            user.save(update_fields=[ api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME ])
            # Give a way to let onboarding tasks do their thing with a newly verified user
            cache.set('newuser_{}'.format(user.id), user.email, timeout=None)
        return True
    elif token.to_alias_type == 'MOBILE':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME) and \
           not getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME, True)
            user.save(update_fields=[ api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME ])
            # Give a way to let onboarding tasks do their thing with a newly verified user
            cache.set('newuser_{}'.format(user.id), user.email, timeout=None)
        return True

    return False


def inject_template_context(context):
    """
    Injects additional context into email template.
    """
    for processor in api_settings.PASSWORDLESS_CONTEXT_PROCESSORS:
        context.update(processor())
    return context


def send_email_with_callback_token(user, email_token, linkbase, **kwargs):
    """
    Sends a Email to user.email.

    Passes silently without sending in test environment
    """

    if linkbase is None:
        linkbase = api_settings.PASSWORDLESS_PROD_LINK_BASE
    
    try:
        if api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
            # Make sure we have a sending address before sending.

            # Get email subject and message
            email_subject = kwargs.get('email_subject',
                                       api_settings.PASSWORDLESS_EMAIL_SUBJECT)
            email_plaintext = kwargs.get('email_plaintext',
                                         api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE)
            email_html = kwargs.get('email_html',
                                    api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME)

            # Inject context if user specifies.
            context = inject_template_context({'callback_token': email_token.key,
                                               'callback_linkbase': linkbase })

            plain_message_template = Template(email_plaintext)
            html_message = loader.render_to_string(email_html, context)

            dest_address = getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)
            
            # UTF-8 is not allowed on Amazon SES in the domain-part, it has to be Punycode (IDNA) encoded
            # https://docs.aws.amazon.com/ses/latest/DeveloperGuide/ses-errors.html
            # Only the domain-part can be punycoded, not the user part!
            
            if '@' in dest_address:
                email_destuser, email_destdomain = dest_address.split('@')
                email_dest = '{}@{}'.format(email_destuser, email_destdomain.encode('idna').decode('ascii'))
            else:
                logger.error("Failed to extract user and domain from %s" % (dest_address))
                return False

            #print('Sending to {}'.format(email_dest))
            
            send_mail(
                email_subject,
                plain_message_template.render(Context(context)),
                api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
                [ email_dest ],
                fail_silently=False,
                html_message=html_message,)

        else:
            logger.debug("Failed to send token email. Missing PASSWORDLESS_EMAIL_NOREPLY_ADDRESS.")
            return False
        return True

    except Exception as e:
        logger.error("Failed to send token email to user %d, "
                  "possibly no email on user object. Email entered was %s" %
                  (user.id, getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)))
        logger.debug(e)
        return False


def send_sms_with_callback_token(user, mobile_token, linkbase, **kwargs):
    """
    Sends a SMS to user.mobile via Twilio.

    Passes silently without sending in test environment.
    """
    base_string = kwargs.get('mobile_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)

    if linkbase is None:
        linkbase = api_settings.PASSWORDLESS_PROD_LINK_BASE
    
    try:

        if api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER and api_settings.PASSWORDLESS_TWILIO_AUTH_TOKEN:

            # We need a sending number to send properly
            if api_settings.PASSWORDLESS_TEST_SUPPRESSION is True:
                # we assume success to prevent spamming SMS during testing.
                return True

            from twilio.rest import Client
            twilio_client = Client(api_settings.PASSWORDLESS_TWILIO_ACCOUNT_SID, api_settings.PASSWORDLESS_TWILIO_AUTH_TOKEN)
            #print('Trying to send SMS to {}'.format(getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)))
            twilio_client.messages.create(
                body=base_string % (linkbase, mobile_token.key),
                to=getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME),
                from_=api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER
            )
            return True
        else:
            logger.error("Failed to send token sms. Missing PASSWORDLESS_MOBILE_NOREPLY_NUMBER.")
            return False
    except ImportError:
        logger.error("Couldn't import Twilio client. Is twilio installed?")
        return False
    except KeyError:
        logger.error("Couldn't send SMS."
                     "Did you set your Twilio account tokens and specify a PASSWORDLESS_MOBILE_NOREPLY_NUMBER?")
        return False
    except Exception as e:
        add_breadcrumb(message='Failed to send Twilio SMS',
                       category='login',
                       data={
                           'error': str(e)
                       })
        # This will also send to Sentry
        logger.error("Failed to send token SMS to user {} and mobile {}".format(user.id,
                                                                                getattr(user,
                                                                                        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)))
        logger.info(e)
        return False
