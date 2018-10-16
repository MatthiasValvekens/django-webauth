from django.utils import translation
from django.contrib.auth.signals import user_logged_in
default_app_config = 'webauth.apps.WebAuthConfig'


def set_session_language(**kwargs):
    user_language = kwargs['user'].lang
    translation.activate(user_language)
    kwargs['request'].session[translation.LANGUAGE_SESSION_KEY] = user_language


user_logged_in.connect(set_session_language)
