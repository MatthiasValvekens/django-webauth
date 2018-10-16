from django import template
from django.conf import settings
from django.utils.translation import ugettext as _
from django.template.base import (
    Node, TemplateSyntaxError, FilterExpression, kwarg_re
)

from webauth.utils import strip_lang as _strip_lang, login_redirect_url

register = template.Library()


@register.filter
def strip_domain(email):
    return email[:email.index('@')]


@register.filter
def strip_lang(path):
    return _strip_lang(path)


# from https://www.caktusgroup.com/blog/2017/05/01/
# building-custom-block-template-tag/
def parse_tag_args(parser, parts):
    args = []
    kwargs = {}
    for part in parts:
        match = kwarg_re.match(part)
        kwarg_format = match and match.group(1)
        if kwarg_format:
            key, value = match.groups()
            kwargs[key] = FilterExpression(value, parser)
        else:
            args.append(FilterExpression(part, parser))

    return args, kwargs


def parse_otprequired(parser, token):
    nodelist = parser.parse(('endotprequired',))
    parts = token.split_contents()
    parts.pop(0)
    if len(parts) > 3:
        raise TemplateSyntaxError(
            "'parse_otprequired' takes at most 3 arguments"
        )
    args, kwargs = parse_tag_args(parser, parts)
    parser.delete_first_token()  # ignore end tag
    return OtpRequiredNode(nodelist, *args, **kwargs)


SPAN_TEMPLATE = '<span class="%s"></span>'
LINK_TEMPLATE_WITH_CLASS = (
    '<a href="%(url)s" class="%(class)s">%(link_text)s</a>'
)
LINK_TEMPLATE_WITHOUT_CLASS = (
    '<a href="%(url)s">%(link_text)s</a>'
)


class OtpRequiredNode(Node):
    def __init__(self, nodelist, 
                 link_class=None, span_class=None, link_text=None, exempt=None):
        self.nodelist = nodelist
        self.link_class = link_class
        self.span_class = span_class
        self.link_text = link_text
        self.exempt = exempt

    def render(self, context):
        try:
            request = context['request']
        except KeyError:
            return ''

        exempted = self.exempt and (
            request.user == self.exempt.resolve(context)
        )

        if request.user.is_verified() or exempted:
            return self.nodelist.render(context)
        else:
            link_text = (
                self.link_text.resolve(context) 
                if self.link_text else _('2FA required')
            )

            if self.span_class:
                span_class = self.span_class.resolve(context)
            else:
                span_class = getattr(settings, 'OTP_REDIRECT_SPAN_CLASS', '')

            if span_class:
                link_text = (SPAN_TEMPLATE % span_class) + link_text

            url = login_redirect_url(request.get_full_path(), otp=True)
            args = {'url': url, 'link_text': link_text}
            if self.link_class:
                link_class = self.link_class.resolve(context)
            else:
                link_class = getattr(settings, 'OTP_REDIRECT_LINK_CLASS', '')

            if link_class:
                args['class'] = link_class
                return LINK_TEMPLATE_WITH_CLASS % args
            else:
                return LINK_TEMPLATE_WITHOUT_CLASS % args


register.tag('otprequired', parse_otprequired)
