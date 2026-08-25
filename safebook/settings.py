"""Settings for SafeBook.

Nothing secret is written in this file. The two secrets - Django's
SECRET_KEY and the server KEK - come from the environment, and .env is not
tracked. See .env.example.
"""

import os
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(DEBUG=(bool, False))
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

SECRET_KEY = env("SECRET_KEY", default=None)
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. Copy .env.example to .env and fill it in - "
        "`python manage.py new_keys` prints a fresh pair."
    )

DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["127.0.0.1", "localhost", "[::1]"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "secureapp",
    "keymgmt",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "safebook.urls"
WSGI_APPLICATION = "safebook.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "secureapp" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {"default": env.db(default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")}

AUTH_USER_MODEL = "secureapp.Account"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Argon2id first: memory hard, so a stolen database is not a wordlist race.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# The KEK wraps the content key of every public post. It is never written to
# the database and never leaves this process.
APP_KEK_BASE64 = env("APP_KEK_BASE64", default=None)
if not APP_KEK_BASE64:
    raise RuntimeError(
        "APP_KEK_BASE64 is not set. Copy .env.example to .env and fill it in - "
        "`python manage.py new_keys` prints a fresh pair."
    )
KEYMGMT_ACTIVE_KEK_ID = env.int("KEYMGMT_ACTIVE_KEK_ID", default=1)

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "secureapp" / "static"]

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"

# A session is the window in which the server can read your data, so it is
# short and it ends when the browser does.
SESSION_COOKIE_AGE = 60 * 60 * 8
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

# Off for a local run over plain http; on everywhere else.
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=not DEBUG)
SECURE_HSTS_SECONDS = 0 if DEBUG else 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
