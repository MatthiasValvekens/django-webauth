from django.db.models import EmailField as BaseEmailField
from django.conf import settings

USE_CITEXT = getattr(settings, 'WEBAUTH_EMAIL_CITEXT', False)

class EmailField(BaseEmailField):
    
    def get_internal_type(self):
        if USE_CITEXT:
            return 'CI' + super().get_internal_type()
        else:
            return super().get_internal_type()

    def db_type(self, connection):
        if USE_CITEXT and connection.vendor == 'postgresql':
            return 'citext'
        else:
            return super().db_type(connection)
