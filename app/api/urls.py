# app/user_keycloak/example_urls.py
"""
URLs for example views
"""

from django.urls import path
from . import views

app_name = 'api'

urlpatterns = [
	# Public endpoints
	path('public/', views.public_view, name='public'),
	# Protected endpoints
	path('protected/', views.protected_view, name='protected'),
	path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
	# Role-based endpoints
	path('admin-area/', views.admin_view, name='admin'),
	path('staff-area/', views.staff_view, name='staff'),
	path('manager-area/', views.manager_view, name='manager'),
	path('admin-or-manager/', views.admin_or_manager_view, name='admin_or_manager'),
	path('admin-auditor/', views.admin_auditor_view, name='admin_auditor'),
	# API endpoints
	path('api/profile/', views.api_user_profile, name='api_profile'),
]
