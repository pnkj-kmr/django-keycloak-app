# auth_urls.py
"""
URL configuration for Keycloak authentication with Redis
"""

from django.urls import path
from . import auth_views as views

app_name = 'keycloak_auth'

urlpatterns = [
	# Main authentication flows
	path('login/', views.keycloak_login, name='login'),
	path('logout/', views.keycloak_logout, name='logout'),
	path('callback/', views.keycloak_callback, name='callback'),
	# Token management
	path('refresh/', views.refresh_token, name='refresh'),
	path('user-info/', views.user_info, name='user_info'),
	path('status/', views.auth_status, name='status'),
	# Admin and monitoring
	path('health/redis/', views.redis_health, name='redis_health'),
	path('admin/invalidate-session/', views.invalidate_user_session, name='invalidate_session'),
]
