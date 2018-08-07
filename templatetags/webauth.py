from django import template

from webauth.utils import strip_lang as _strip_lang

register = template.Library()


@register.filter
def strip_lang(path):
    return _strip_lang(path)
