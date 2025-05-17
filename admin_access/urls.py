# otp_admin_backend/urls.py
from django.urls import path
from admin_access.views import LoginView, OTPVerifyView
from .views import get_csrf_token


urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify_otp'),
path('api/csrf/', get_csrf_token, name='csrf'),]


