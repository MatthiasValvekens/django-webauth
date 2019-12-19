from webauth import tokens

class SimpleTBUrlTokenGenerator(tokens.TimeBasedUrlTokenGenerator):

    def __init__(self, *, stuff: int, **kwargs):
        self.stuff = stuff
        super().__init__(**kwargs)
