from django.core.cache import cache
from django.http import HttpResponse
from rest_framework import status
import time

class IPRateLimitMiddleware:
    """Middleware to limit the number of requests from a single IP address."""
    def __init__(self, get_response):
        self.get_response = get_response
        self.cache_timeout = 60
        self.max_requests = 60

    def __call__(self, request):
        ip = self.get_client_ip(request)
        if not self.is_rate_limited(ip):
            return self.get_response(request)
        return HttpResponse("Rate limit exceeded", status=status.HTTP_429_TOO_MANY_REQUESTS)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

    def is_rate_limited(self, ip):
        cache_key = f'rate_limit_{ip}'
        requests = cache.get(cache_key, [])
        now = time.time()
        requests = [req for req in requests if now - req < self.cache_timeout]
        if len(requests) >= self.max_requests:
            return True
        requests.append(now)
        cache.set(cache_key, requests, self.cache_timeout)
        return False
