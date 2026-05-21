import sys
import types


def pytest_configure():
    from django.conf import settings
    from rest_framework import serializers

    glimra_module = types.ModuleType('glimra')
    base_module = types.ModuleType('glimra.base')
    fields_module = types.ModuleType('glimra.base.fields')

    class PhoneNumberSerializerField(serializers.RegexField):
        def __init__(self, **kwargs):
            super().__init__(r'^\+?1?\d{9,15}$', **kwargs)

    fields_module.PhoneNumberSerializerField = PhoneNumberSerializerField
    sys.modules.setdefault('glimra', glimra_module)
    sys.modules.setdefault('glimra.base', base_module)
    sys.modules.setdefault('glimra.base.fields', fields_module)

    settings.configure(
        DEBUG_PROPAGATE_EXCEPTIONS=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:'
            }
        },
        SITE_ID=1,
        SECRET_KEY='_',
        USE_I18N=True,
        USE_L10N=True,
        STATIC_URL='/static/',
        ROOT_URLCONF='tests.urls',
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                        'django.contrib.auth.context_processors.auth',
                        'django.contrib.messages.context_processors.messages',
                    ],
                },
            },
        ],
        MIDDLEWARE=(
            'django.middleware.common.CommonMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
        ),
        INSTALLED_APPS=(
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.sites',
            'django.contrib.messages',
            'django.contrib.staticfiles',
            'rest_framework',
            'rest_framework.authtoken',
            'drfpasswordless',
            'tests',
        ),
        PASSWORD_HASHERS=(
            'django.contrib.auth.hashers.MD5PasswordHasher',
        ),
        AUTH_USER_MODEL='tests.CustomUser',
    )

    try:
        import django
        django.setup()
    except AttributeError:
        pass
