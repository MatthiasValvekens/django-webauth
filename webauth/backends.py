from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from webauth.models import User

class EmailOrLegacyUsernameModelBackend(ModelBackend):
    """
    Log in via email (default) or username (for backwards compatibility)
    """
 
    def authenticate(self, request, username=None, password=None):
        try:
            if '@' in username: 
                user = User.objects.get(email=username)
            else:
                user = User.objects.get(legacy_username=username)
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            User().set_password(password)
            return None
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def get_user(self, user_id):
        qs = User.objects
        if hasattr(settings, 'WEBAUTH_GET_USER_JOINS'):
            qs = qs.select_related(*settings.WEBAUTH_GET_USER_JOINS)
        try:
            user = qs.get(pk=user_id)
        except User.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None 
