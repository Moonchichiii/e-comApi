from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.contrib.auth import get_user_model

User = get_user_model()

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """Custom admin interface for User model with enhanced features and organization."""
    
    # List display configuration
    list_display = (
        'email', 
        'get_full_name', 
        'is_active', 
        'email_verified',
        'account_status',
        'last_login',
        'get_failed_attempts',
        'date_joined'
    )
    
    # List filter configuration
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'email_verified',
        'require_password_change',
        ('last_login', admin.EmptyFieldListFilter),
        'date_joined',
    )
    
    # Search configuration
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)  # Changed from 'username' to 'date_joined'
    
    # Fields to display in the admin form
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        (_('Personal info'), {
            'fields': ('first_name', 'last_name')
        }),
        (_('Account Status'), {
            'fields': (
                'is_active',
                'email_verified',
                'require_password_change',
            )
        }),
        (_('Security Information'), {
            'fields': (
                'failed_login_attempts',
                'lockout_until',
                'last_password_change',
            )
        }),
        (_('Important dates'), {
            'fields': ('last_login', 'date_joined')
        }),
        (_('Permissions'), {
            'fields': (
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions'
            ),
            'classes': ('collapse',)
        }),
    )
    
    # Fields for adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email',
                'password1',
                'password2',
                'first_name',
                'last_name',
                'is_active',
                'is_staff',
                'email_verified'
            ),
        }),
    )
    
    readonly_fields = (
        'last_login',
        'date_joined',
        'last_password_change',
        'failed_login_attempts',
        'lockout_until'
    )
    
    def get_failed_attempts(self, obj):
        """Display failed login attempts with warning colors."""
        style = """
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-weight: 500;
            text-align: center;
            min-width: 60px;
        """
        
        if obj.failed_login_attempts == 0:
            style += "background-color: rgba(39, 174, 96, 0.2); color: #27ae60;"
            text = '0'
        elif obj.failed_login_attempts < 3:
            style += "background-color: rgba(243, 156, 18, 0.2); color: #f39c12;"
            text = str(obj.failed_login_attempts)
        else:
            style += "background-color: rgba(231, 76, 60, 0.2); color: #e74c3c;"
            text = str(obj.failed_login_attempts)
        
        return format_html('<span style="{}">{}</span>', style, text)
    get_failed_attempts.short_description = _('Failed Attempts')
    
    def account_status(self, obj):
        """Display account status with styled indicators."""
        base_style = """
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 500;
            text-align: center;
            min-width: 80px;
        """
        
        if not obj.is_active:
            style = base_style + "background-color: rgba(231, 76, 60, 0.2); color: #e74c3c;"
            return format_html('<span style="{}">{}</span>', style, 'Inactive')
        
        if obj.lockout_until:
            style = base_style + "background-color: rgba(231, 76, 60, 0.2); color: #e74c3c;"
            return format_html('<span style="{}">{}</span>', style, 'Locked')
        
        if not obj.email_verified:
            style = base_style + "background-color: rgba(243, 156, 18, 0.2); color: #f39c12;"
            return format_html('<span style="{}">{}</span>', style, 'Unverified')
        
        style = base_style + "background-color: rgba(39, 174, 96, 0.2); color: #27ae60;"
        return format_html('<span style="{}">{}</span>', style, 'Active')
    account_status.short_description = _('Status')
    
    # Custom actions
    actions = ['unlock_users', 'verify_emails', 'reset_failed_attempts']
    
    @admin.action(description=_('Unlock selected users'))
    def unlock_users(self, request, queryset):
        """Unlock selected users by resetting their lockout status."""
        updated = queryset.update(
            lockout_until=None,
            failed_login_attempts=0
        )
        self.message_user(
            request,
            _(f'{updated} users were successfully unlocked.')
        )
    
    @admin.action(description=_('Verify selected users\' emails'))
    def verify_emails(self, request, queryset):
        """Mark selected users' emails as verified."""
        updated = queryset.update(email_verified=True)
        self.message_user(
            request,
            _(f'{updated} users were successfully verified.')
        )
    
    @admin.action(description=_('Reset failed login attempts'))
    def reset_failed_attempts(self, request, queryset):
        """Reset failed login attempts for selected users."""
        updated = queryset.update(failed_login_attempts=0)
        self.message_user(
            request,
            _(f'Failed login attempts reset for {updated} users.')
        )

    def changelist_view(self, request, extra_context=None):
        """Add custom styles to the changelist view."""
        extra_context = extra_context or {}
        extra_context['title'] = 'User Management'
        
        # Add inline styles for the admin interface
        extra_context['extra_style'] = """
            <style>
                #changelist table thead th {
                    background: #2c3e50;
                    color: white;
                    padding: 12px 8px;
                }
                
                #changelist table tbody tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                
                #changelist table tbody tr:hover {
                    background-color: #f5f5f5;
                }
                
                .submit-row input {
                    padding: 10px 15px;
                    border-radius: 4px;
                }
                
                .button, input[type=submit], input[type=button] {
                    background: #3498db;
                    color: white;
                    border: none;
                    padding: 8px 12px;
                    border-radius: 4px;
                    cursor: pointer;
                }
                
                .button:hover, input[type=submit]:hover, input[type=button]:hover {
                    background: #2980b9;
                }
                
                .module h2, .module caption {
                    background: #34495e;
                    color: white;
                    padding: 12px;
                }
            </style>
        """
        return super().changelist_view(request, extra_context)

    def change_view(self, request, object_id, form_url='', extra_context=None):
        """Add custom styles to the change view."""
        extra_context = extra_context or {}
        extra_context['extra_style'] = """
            <style>
                .form-row {
                    padding: 12px;
                    border-bottom: 1px solid #eee;
                }
                
                .submit-row {
                    background: white;
                    padding: 15px;
                    box-shadow: 0 -1px 3px rgba(0,0,0,0.1);
                }
                
                .field-box {
                    margin-right: 20px;
                    padding: 10px;
                }
                
                .help {
                    color: #666;
                    font-size: 0.9em;
                    padding: 5px 0;
                }
                
                select {
                    padding: 6px;
                    border-radius: 4px;
                    border: 1px solid #ddd;
                }
            </style>
        """
        return super().change_view(request, object_id, form_url, extra_context)