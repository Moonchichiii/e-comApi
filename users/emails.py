from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

def send_verification_email(user):
    """Send verification email to the user."""
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    verification_url = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}"
    context = {
        'user': user,
        'verification_url': verification_url,
    }
    message = render_to_string('email/verification.html', context)
    send_mail(
        'Verify your email address',
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message,
    )
