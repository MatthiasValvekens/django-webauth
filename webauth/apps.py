from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _ 

class WebAuthConfig(AppConfig):
    name = 'webauth'
    verbose_name = _('WebAuth authentication layer')
