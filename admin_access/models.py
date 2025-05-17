from django.contrib.auth.models import AbstractUser
from django.db import models

class AdminUser(AbstractUser):
    ROLE_CHOICES = [
        ('menu', 'Menu Admin'),
        ('recipe', 'Recipe Admin'),
        ('order', 'Order Admin'),
        ('superadmin', 'Super Admin'),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)  # For expiry check
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username
