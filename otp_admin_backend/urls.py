from django.contrib import admin
from django.urls import path, include
from admin_access.views import get_csrf_token  # ✅ Import here

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('admin_access.urls')),
    path('api/csrf/', get_csrf_token, name='csrf')  # ✅ Register route
]
