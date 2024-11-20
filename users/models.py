"""Custom user model with email authentication and enhanced security features."""

import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import EmailValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""
    
    def create_user(self, email: str, password: str = None, **extra_fields) -> 'User':
        """Create and save a regular user.
        
        Args:
            email: User's email address
            password: User's password
            **extra_fields: Additional fields for User model
            
        Returns:
            User: Created user instance
            
        Raises:
            ValueError: If email is not provided
        """
        if not email:
            raise ValueError(_('Email address is required'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str = None, **extra_fields) -> 'User':
        """Create and save a superuser.
        
        Args:
            email: Superuser's email address
            password: Superuser's password
            **extra_fields: Additional fields for User model
            
        Returns:
            User: Created superuser instance
            
        Raises:
            ValueError: If is_staff or is_superuser is not True
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model with email as the username field and enhanced security features."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_('Unique identifier for the user')
    )
    email = models.EmailField(
        _('email address'),
        unique=True,
        validators=[EmailValidator()],
        error_messages={
            'unique': _('A user with that email already exists.'),
        },
        help_text=_('Required. The email address will be used for logging in.')
    )
    first_name = models.CharField(
        _('first name'),
        max_length=150,
        blank=True,
        help_text=_('User\'s first name')
    )
    last_name = models.CharField(
        _('last name'),
        max_length=150,
        blank=True,
        help_text=_('User\'s last name')
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.')
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_('Designates whether this user should be treated as active.')
    )
    email_verified = models.BooleanField(
        _('email verified'),
        default=False,
        help_text=_('Designates whether this user has verified their email address.')
    )
    date_joined = models.DateTimeField(
        _('date joined'),
        default=timezone.now,
        help_text=_('Date and time when the user joined')
    )
    last_login = models.DateTimeField(
        _('last login'),
        null=True,
        blank=True,
        help_text=_('Date and time of the user\'s last login')
    )
    last_password_change = models.DateTimeField(
        _('last password change'),
        null=True,
        blank=True,
        help_text=_('Date and time of the last password change')
    )
    failed_login_attempts = models.PositiveIntegerField(
        _('failed login attempts'),
        default=0,
        help_text=_('Number of consecutive failed login attempts')
    )
    lockout_until = models.DateTimeField(
        _('lockout until'),
        null=True,
        blank=True,
        help_text=_('Timestamp until when the user is locked out')
    )
    password_changed_at = models.DateTimeField(
        _('password changed at'),
        auto_now_add=True,
        help_text=_('Timestamp of when the password was last changed')
    )
    require_password_change = models.BooleanField(
        _('require password change'),
        default=False,
        help_text=_('Indicates if the user must change their password on next login')
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['date_joined']),
        ]

    def __str__(self) -> str:
        """Get string representation of the user.
        
        Returns:
            str: User's email address
        """
        return str(self.email)

    def get_full_name(self) -> str:
        """Get user's full name.
        
        Returns:
            str: User's full name (first name + last name)
        """
        return f'{self.first_name} {self.last_name}'.strip()

    def get_short_name(self) -> str:
        """Get user's short name.
        
        Returns:
            str: User's first name
        """
        return self.first_name

    def increment_failed_login_attempts(self) -> None:
        """Increment failed login attempts and handle lockout.
        
        If the number of failed attempts exceeds the limit,
        the user will be locked out for one hour.
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= settings.AXES_FAILURE_LIMIT:
            self.lockout_until = timezone.now() + timedelta(hours=1)
        self.save(update_fields=['failed_login_attempts', 'lockout_until'])

    def reset_failed_login_attempts(self) -> None:
        """Reset the failed login attempts counter and remove lockout."""
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.save(update_fields=['failed_login_attempts', 'lockout_until'])

    def set_password(self, raw_password: str) -> None:
        """Set the user's password and update related fields.
        
        Args:
            raw_password: The new password in plain text
        """
        super().set_password(raw_password)
        self.password_changed_at = timezone.now()
        self.require_password_change = False
        
    def is_locked_out(self) -> bool:
        """Check if the user is currently locked out.
        
        Returns:
            bool: True if the user is locked out, False otherwise
        """
        if not self.lockout_until:
            return False
        return timezone.now() < self.lockout_until