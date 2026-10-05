<h1>Changelog</h1>
<h2>4.0.0</h2>
This release replaces the deprecated <code>authlib</code> dependency with <code>joserfc</code> directly, and drops Python 3.7-3.9 support (requires Python 3.10 or newer).

JWT signature verification now only accepts tokens whose <code>alg</code> is listed in the new <code>JWT_ALGORITHMS</code> setting (default: <code>RS256</code>). Tokens using other algorithms, including unsigned ones, are rejected before verification. Tokens with a malformed header, or with an unknown <code>kid</code>, are now rejected with a 401 instead of raising a 500. Claim validation (<code>exp</code>, <code>iat</code>, <code>iss</code>, <code>aud</code>) is enforced explicitly and no longer depends on authlib version-specific leeway semantics. The algorithms can be configured with:

```
'OIDC_AUTH': {
    ...
    'JWT_ALGORITHMS': ('RS256',),
}
```

Packaging moved to <code>pyproject.toml</code> with a <code>uv.lock</code>, and the package is published to PyPI automatically when a GitHub release is published.

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
