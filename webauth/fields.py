from django.db.models import EmailField as BaseEmailField
from django.conf import settings

USE_CITEXT = getattr(settings, 'WEBAUTH_EMAIL_CITEXT', False)


class EmailField(BaseEmailField):
    def db_type(self, connection):
        if USE_CITEXT and connection.vendor == 'postgresql':
            return 'citext'
        return super().db_type(connection)
