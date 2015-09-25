from setuptools import setup

setup(
    name='drf-oidc-auth',
    version='0.2',
    packages=['oidc_auth'],
    url='https://github.com/ByteInternet/drf-oidc-auth',
    license='MIT',
    author='Maarten van Schaik',
    author_email='maarten@byte.nl',
    description='OpenID Connect authentication for Django Rest Framework',
    install_requires=[
        'pyjwkest>=1.0.3',
        'django>=1.6.0',
        'djangorestframework>=2.4.0',
    ]
)
