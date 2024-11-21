"""
Views for user authentication, registration, and profile management.
Includes email verification and social authentication functionality.
"""

from typing import Any, TypeVar, cast
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpRequest
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django_ratelimit.decorators import ratelimit
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from social_core.exceptions import MissingBackend, AuthException
from social_django.utils import load_strategy, load_backend

from .serializers import (
    UserSerializer,
    UserCreateSerializer as UserRegisterSerializer,
    CustomTokenObtainPairSerializer,
)

UserType = TypeVar('UserType', bound='User')
User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token view that updates last login timestamp and handles rate limiting."""

    serializer_class = CustomTokenObtainPairSerializer

    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """Handle POST request for token generation.

        Args:
            request: The HTTP request object
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Response: JWT token response or error response
        """
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            user = cast(UserType, User.objects.get(email=request.data['email']))
            user.last_login = timezone.now()
            user.reset_failed_login_attempts()
            user.save(update_fields=['last_login', 'failed_login_attempts', 'lockout_until'])
        return response


class RegisterView(generics.CreateAPIView):
    """Handle user registration with rate limiting."""

    permission_classes = (AllowAny,)
    serializer_class = UserRegisterSerializer

    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """Handle POST request for user registration.

        Args:
            request: The HTTP request object
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Response: User creation response or error response
        """
        return super().post(request, *args, **kwargs)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """Handle user profile retrieval and updates."""

    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self) -> UserType:
        """Get the authenticated user's profile.

        Returns:
            UserType: The authenticated user instance
        """
        return cast(UserType, self.request.user)


class VerifyEmailView(APIView):
    """Handle email verification through token validation."""

    permission_classes = (AllowAny,)

    def get(self, request: HttpRequest, uidb64: str, token: str) -> Response:
        """Handle GET request for email verification.

        Args:
            request: The HTTP request object
            uidb64: Base64 encoded user ID
            token: Verification token

        Returns:
            Response: Success response or error response
        """
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = cast(UserType, User.objects.get(pk=uid))
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'detail': 'Invalid verification link.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if user and default_token_generator.check_token(user, token):
            if user.email_verified:
                return Response({'detail': 'Email already verified.'})

            user.email_verified = True
            user.save(update_fields=['email_verified'])
            return Response({'detail': 'Email successfully verified.'})

        return Response(
            {'detail': 'Invalid verification link.'},
            status=status.HTTP_400_BAD_REQUEST
        )


class SocialLoginView(APIView):
    """Handle social authentication through various providers."""

    permission_classes = (AllowAny,)
    ALLOWED_BACKENDS = ['google-oauth2', 'facebook']

    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request: HttpRequest, backend: str) -> Response:
        """Handle POST request for social authentication.

        Args:
            request: The HTTP request object
            backend: Name of the social auth backend

        Returns:
            Response: Authentication response with tokens or error response
        """
        if backend not in self.ALLOWED_BACKENDS:
            return Response(
                {'detail': 'Invalid social auth provider'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            strategy = load_strategy(request)
            auth_backend = load_backend(
                strategy=strategy,
                name=backend,
                redirect_uri=None
            )

            token = request.data.get('access_token')
            if not token:
                return Response(
                    {'detail': 'Access token is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = auth_backend.do_auth(token)
            if not user:
                return Response(
                    {'detail': 'Authentication failed'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = cast(UserType, user)
            self._update_user_social_data(user, backend)
            return self._generate_auth_response(user)

        except MissingBackend:
            return Response(
                {'detail': 'Invalid social auth provider'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except AuthException as auth_error:
            return Response(
                {'detail': str(auth_error)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception:  # pylint: disable=broad-except
            return Response(
                {'detail': 'Authentication failed'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _update_user_social_data(self, user: UserType, backend: str) -> None:
        """Update user's social authentication data.

        Args:
            user: The user instance to update
            backend: Name of the social auth backend
        """
        user.email_verified = True
        user.social_provider = backend
        user.last_login = timezone.now()
        user.save(update_fields=['email_verified', 'social_provider', 'last_login'])

    def _generate_auth_response(self, user: UserType) -> Response:
        """Generate authentication response with tokens.

        Args:
            user: The authenticated user instance

        Returns:
            Response: Authentication response with tokens and user data
        """
        token = CustomTokenObtainPairSerializer.get_token(user)
        return Response({
            'access': str(token.access_token),
            'refresh': str(token),
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email_verified': user.email_verified
            }
        })
        
class CurrentUserView(APIView):
    """Return the authenticated user's information."""
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        data = {
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email_verified': user.email_verified,
        }
        return Response(data, status=status.HTTP_200_OK)
        

def csp_report(request):
    """Log or process CSP violation reports."""
    return JsonResponse({"status": "CSP report received."}, status=200)
