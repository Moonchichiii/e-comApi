from datetime import timedelta
from django.utils import timezone
from rest_framework import permissions

class IsVerifiedUser(permissions.BasePermission):
    """Allows access only to verified users."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.email_verified)

class IsActiveUser(permissions.BasePermission):
    """Allows access only to active users."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_active)

class HasValidToken(permissions.BasePermission):
    """Checks if the user's token is still valid."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        last_login = request.user.last_login
        if not last_login:
            return False
        return timezone.now() - last_login < timedelta(days=7)

