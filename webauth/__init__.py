from django.conf import settings
from django.utils import translation
from django.contrib.auth.signals import user_logged_in
default_app_config = 'webauth.apps.WebAuthConfig'


def set_session_language(**kwargs):
    user_language = kwargs['user'].lang
    translation.activate(user_language)
    kwargs['request'].COOKIES[settings.LANGUAGE_COOKIE_NAME] = user_language


user_logged_in.connect(set_session_language)
