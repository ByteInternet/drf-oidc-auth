from setuptools import setup

setup(
    name='drf-oidc-auth',
    version='2.0.0',
    packages=['oidc_auth'],
    url='https://github.com/ByteInternet/drf-oidc-auth',
    license='MIT',
    author='Maarten van Schaik',
    author_email='support@byte.nl',
    description='OpenID Connect authentication for Django Rest Framework',
    install_requires=[
        'authlib>=0.15.0',
        'cryptography>=2.6',
        'django>=1.8.0',
        'djangorestframework>=3.0.0',
        'requests>=2.20.0'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],
)
