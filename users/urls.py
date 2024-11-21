"""Authentication URLs."""
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView,
    CustomTokenObtainPairView,
    UserProfileView,
    VerifyEmailView,
    SocialLoginView,
    CurrentUserView,
    )
from .views import csp_report

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('current-user/', CurrentUserView.as_view(), name='current_user'),
    path('verify-email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),    
    path('social/<str:backend>/', SocialLoginView.as_view(), name='social_login'),    
    path("csp-report/", csp_report, name="csp_report"),
]
