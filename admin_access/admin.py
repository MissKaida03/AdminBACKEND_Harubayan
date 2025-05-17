from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import AdminUser

@admin.register(AdminUser)
class CustomAdminUser(UserAdmin):
    model = AdminUser
    list_display = ('username', 'email', 'role', 'is_verified', 'is_staff')
    list_filter = ('role', 'is_verified', 'is_staff')
    
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'role', 'otp_code', 'is_verified')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'role', 'password1', 'password2', 'is_verified'),
        }),
    )

    search_fields = ('username', 'email')
    ordering = ('username',)
