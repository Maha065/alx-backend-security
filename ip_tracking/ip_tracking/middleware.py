from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache
from ipgeolocation import IPGeolocationAPI
from .models import RequestLog, BlockedIP

# Replace this with your IPGeolocation.io API key if configured
API_KEY = 'your_api_key_here'

class IPTrackingMiddleware:
    """Middleware to block blacklisted IPs and log request data with geolocation."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo_api = IPGeolocationAPI(API_KEY)

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block IP if blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: Your IP is blocked.")

        # Try to get geolocation (with caching)
        location = self.get_geolocation(ip_address)

        # Log the request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            timestamp=timezone.now(),
            country=location.get("country_name"),
            city=location.get("city")
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip

    def get_geolocation(self, ip_address):
        """Get geolocation data from API or cache it for 24 hours."""
        cache_key = f"geo_{ip_address}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            geo_data = self.geo_api.get_geolocation(ip_address=ip_address)
            country = geo_data.get("country_name")
            city = geo_data.get("city")
        except Exception:
            country, city = None, None

        result = {"country_name": country, "city": city}
        cache.set(cache_key, result, 60 * 60 * 24)  # cache for 24 hours
        return result
