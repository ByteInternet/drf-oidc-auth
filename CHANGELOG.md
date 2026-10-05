<h1>Changelog</h1>
<h2>3.1.0</h2>
Security hardening: JWT signature verification now only accepts tokens whose <code>alg</code> is listed in the new <code>JWT_ALGORITHMS</code> setting (default: <code>RS256</code>). Tokens using other algorithms, including unsigned ones, are rejected before verification. Tokens with a malformed or non-object header, and tokens with an unknown <code>kid</code>, are now rejected with a 401 instead of raising a 500. The algorithms can be configured with:

```
'OIDC_AUTH': {
    ...
    'JWT_ALGORITHMS': ('RS256',),
}
```

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
