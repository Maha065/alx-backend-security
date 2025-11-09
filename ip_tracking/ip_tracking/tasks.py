from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from ip_tracking.models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Detects suspicious IPs based on:
      1. More than 100 requests in the last hour.
      2. Accessing sensitive paths such as /admin or /login.
    Runs hourly via Celery.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # 1️⃣ IPs exceeding 100 requests/hour
    high_volume_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in high_volume_ips:
        ip = entry['ip_address']
        reason = f"Exceeded 100 requests/hour ({entry['request_count']} requests)"
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})

    # 2️⃣ IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/login']
    suspicious_accesses = RequestLog.objects.filter(
        path__in=sensitive_paths, timestamp__gte=one_hour_ago
    ).values_list('ip_address', flat=True).distinct()

    for ip in suspicious_accesses:
        reason = f"Accessed sensitive path within last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})
