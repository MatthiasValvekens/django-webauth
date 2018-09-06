import re

from django.conf import settings
from django.utils.translation import get_language
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# inspired by https://stackoverflow.com/questions/19080211/internalization-set-language-redirect-view-how-to-redirect-to-the-same-page
LANG_REGEXES = {
    lang[0]: re.compile('^(/%s)/' % lang[0])
    for lang in settings.LANGUAGES
}

def strip_lang(path):
    lang = get_language()
    try:
        match = LANG_REGEXES[lang].search(path)
    except KeyError:
        return path

    if match is None:
        return path
    else:
        return path[match.end(1):]

# change the salt and account for active status
class ActivationTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "webauth.utils.ActivationTokenGenerator"

    def _make_hash_value(self, user, timestamp):
        v = super(ActivationTokenGenerator, self)\
                ._make_hash_value(user, timestamp)
        return v + str(user.is_active)

class UnlockTokenGenerator(ActivationTokenGenerator):
    key_salt = "webauth.utils.UnlockTokenGenerator"
