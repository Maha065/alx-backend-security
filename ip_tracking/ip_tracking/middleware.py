from django.http import HttpResponseForbidden
from django.utils import timezone
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    """Middleware to log requests and block blacklisted IPs."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Check if the IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: Your IP is blocked.")

        # Log the request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            timestamp=timezone.now()
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
