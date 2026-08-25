from pathlib import Path
import environ
import os

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)
environ.Env.read_env(os.path.join(BASE_DIR, ".env")) if os.path.exists(os.path.join(BASE_DIR, ".env")) else None

SECRET_KEY = env("SECRET_KEY", default="dev-insecure")
DEBUG = env.bool("DEBUG", default=True)

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "secureapp",
    "keymgmt",
    "argon2"
    
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

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [ BASE_DIR / "secureapp" / "templates" ],
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

WSGI_APPLICATION = "safebook.wsgi.application"

DATABASES = {
    "default": env.db(default=f"sqlite:///{BASE_DIR/'db.sqlite3'}")
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Use Argon2id first (salted & slow)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [ BASE_DIR / "secureapp" / "static" ]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Custom user (adds key/crypto fields)
AUTH_USER_MODEL = "secureapp.Account"

# Key management: server KEK (base64 -> bytes)
APP_KEK_BASE64 = env("APP_KEK_BASE64", default=None)
if not APP_KEK_BASE64:
    raise RuntimeError("APP_KEK_BASE64 not set in .env (see .env.example)")

# --- Key Management settings ---
KEYMGMT_ACTIVE_KEK_ID = int(os.getenv("KEYMGMT_ACTIVE_KEK_ID", "1"))
USE_RSA_MESSAGES = env.bool("USE_RSA_MESSAGES", default=True)


# Use our custom auth routes
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"


# settings.py (DEV)
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]

SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_PROXY_SSL_HEADER = None  # comment out if you added it
