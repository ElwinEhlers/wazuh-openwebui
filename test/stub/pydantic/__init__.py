class BaseModel:
    def __init__(self, **kw):
        for k in dir(type(self)):
            if not k.startswith('_'):
                v = getattr(type(self), k)
                setattr(self, k, v.default if isinstance(v, _F) else v)
class _F:
    def __init__(self, default=None, **kw): self.default = default
def Field(default=None, **kw): return _F(default)
