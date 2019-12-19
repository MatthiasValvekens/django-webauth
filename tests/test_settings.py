SECRET_KEY = 'fake-key'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'webauth', 'tests',
]

WEBAUTH_UNSUBSCRIBE_EMAIL = 'a@b.com'
AUTH_USER_MODEL = 'webauth.User'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3'
    }
}

ROOT_URLCONF = 'tests.urls'
