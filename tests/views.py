from django.http import HttpResponse
from webauth import tokens

class SimpleTBUrlTokenGenerator(tokens.TimeBasedUrlTokenGenerator):

    def __init__(self, *, stuff: int, **kwargs):
        self.stuff = stuff
        super().__init__(**kwargs)


@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False)
def simple_view(request, stuff: int):
    return HttpResponse(str(stuff))

@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False)
def simple_view_with_more_args(request, stuff: int, foo: str, bar: str):
    return HttpResponse(str(stuff) + str(foo))
