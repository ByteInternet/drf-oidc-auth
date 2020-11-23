<h1>Changelog</h1>
<h2>1.0.0</h2>
Replace the deprecated `jwkest` library with the maintained `authlib` library. Note that this is not backwards compatible, but this might not be immediately obvious. You have to adjust your settings, i.e. `OIDC_AUDIENCES` is deprecated and replaced by:

```
'OIDC_CLAIMS_OPTIONS': {
    'aud': {
        'values': ['my_audience'],
        'essential': True,
    }
}
```

Please note the addition of `essential: True` in this dict. If you leave this out it will mean that _any_ audience will have access to your API. This is probably not what you want, so please make sure you add this to your settings if you're coming from a previous version.

Also note that cryptography needs to be a least version 2.6 to work with the new authlib library.
