# Rate limiting settings
RATELIMIT_USE_CACHE = 'default'  # use default Django cache backend
RATELIMIT_ENABLE = True

# Default rate limits
RATELIMIT_AUTHENTICATED = '10/m'   # 10 requests per minute for logged-in users
RATELIMIT_ANONYMOUS = '5/m'        # 5 requests per minute for anonymous users
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
