from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'PASSWORDLESS_AUTH', None)

DEFAULTS = {

    # Allowed auth types, can be EMAIL, MOBILE, or both.
    'PASSWORDLESS_AUTH_TYPES': ['EMAIL'],

    # These fields are allowed in the 6-digit user-registration API call, to setup a new user (apart from the auth alias type in use)
    'PASSWORDLESS_USER_CREATION_FIELDS': [ ],

    # Which of the creation fields are required when creating a user
    'PASSWORDLESS_USER_CREATION_FIELDS_REQ': [ ],
    
    # Amount of time that the callback tokens last, in seconds
    'PASSWORDLESS_TOKEN_EXPIRE_TIME': 15 * 60,

    # Amount of time that refreshtokens last, in seconds
    'PASSWORDLESS_REFRESHTOKEN_EXPIRE_TIME': 86400 * 90,   # 3 months default

    # If True, give out new refresh tokens every time one is used to get an authtoken, preventing them from expiring as
    # long as they are used regularly
    'PASSWORDLESS_ROTATE_REFRESH_TOKENS': True,
    
    # Amount of time that rest framework authtokens last, in seconds
    'PASSWORDLESS_AUTHTOKEN_EXPIRE_TIME': 86400,   # 24 hours default

    # The user's email field name
    'PASSWORDLESS_USER_EMAIL_FIELD_NAME': 'email',

    # The user's mobile field name
    'PASSWORDLESS_USER_MOBILE_FIELD_NAME': 'mobile',

    # Marks itself as verified the first time a user completes auth via token.
    # Automatically unmarks itself if email is changed.
    'PASSWORDLESS_USER_MARK_EMAIL_VERIFIED': False,
    'PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME': 'email_verified',

    # Marks itself as verified the first time a user completes auth via token.
    # Automatically unmarks itself if mobile number is changed.
    'PASSWORDLESS_USER_MARK_MOBILE_VERIFIED': False,
    'PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME': 'mobile_verified',

    # The email the callback token is sent from
    'PASSWORDLESS_EMAIL_NOREPLY_ADDRESS': None,

    # The email subject
    'PASSWORDLESS_EMAIL_SUBJECT': "Your Login Token",

    'PASSWORDLESS_PROD_LINK_BASE': '',
    'PASSWORDLESS_DEV_LINK_BASE': '',
    'PASSWORDLESS_FI_LINK_BASE': '',

    # A plaintext email message overridden by the html message. Takes one string.
    'PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE': "Enter this token to sign in: %s%s",

    # The email template name.
    'PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME': "passwordless_default_token_email.html",

    # Twilio account credentials
    'PASSWORDLESS_TWILIO_ACCOUNT_SID': None,
    'PASSWORDLESS_TWILIO_AUTH_TOKEN': None,

    # Your twilio number that sends the callback tokens.
    'PASSWORDLESS_MOBILE_NOREPLY_NUMBER': None,

    # The message sent to mobile users logging in. Takes one string.
    'PASSWORDLESS_MOBILE_MESSAGE': "Use this code to log in: %s%s",

    # The message sent to Finnish mobile users logging in. Takes one string.
    'PASSWORDLESS_MOBILE_MESSAGE_FI': "Use this code to log in: %s%s",
    'PASSWORDLESS_MOBILE_MESSAGE_DESKTOP': "Use this code to log in: %s%s",

    # Registers previously unseen aliases as new users.
    'PASSWORDLESS_REGISTER_NEW_USERS': True,

    # Suppresses actual SMS for testing
    'PASSWORDLESS_TEST_SUPPRESSION': False,

    # Context Processors for Email Template
    'PASSWORDLESS_CONTEXT_PROCESSORS': [],

    # The verification email subject
    'PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT': "Your Verification Token",

    # A plaintext verification email message overridden by the html message. Takes one string.
    'PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE': "Enter this verification code: %s",

    # The verification email template name.
    'PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME': "passwordless_default_verification_token_email.html",

    # The message sent to mobile users logging in. Takes one string.
    'PASSWORDLESS_MOBILE_VERIFICATION_MESSAGE': "Enter this verification code: %s",

    # Automatically send verification email or sms when a user changes their alias.
    'PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN': False,

    # Support refresh tokens; after the callback 6-digit token is exchanged, a refresh token is generated and
    # given to the client along with the normal access token. The refresh token can then be used to get new access tokens.
    # Note that this only makes sense if the normal rest framework auth tokens are shortlived by some other mechanism.
    'PASSWORDLESS_USE_REFRESH_TOKENS': False,

    # Reuse existing rest framework auth tokens for a user when such a token is requested. If not using the refresh_token system,
    # and with default non-time-limited auth tokens, it is best to reuse them, otherwise just create new tokens.
    # Note: with the normal rest framework, this can only be set to True (a User can't have multiple Tokens)
    'PASSWORDLESS_REUSE_AUTH_TOKENS': True,

    # Number of digilets newly registred SE users get
    "PASSWORDLESS_SE_NEW_USER_DIGILETS": 0,
    # Number of digilets newly registred FI users get
    "PASSWORDLESS_FI_NEW_USER_DIGILETS": 0,
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE',
    'PASSWORDLESS_CONTEXT_PROCESSORS',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
