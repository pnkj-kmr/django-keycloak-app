# app/user_keycloak/example_views.py
"""
Example views demonstrating Keycloak authentication and permissions
"""

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views import View

from app.user_keycloak.decorators import login_required, role_required, admin_required, staff_required, token_required


# Public view (no authentication required)
def public_view(request):
	"""Public view accessible to everyone"""
	return JsonResponse(
		{
			'message': 'This is a public endpoint',
			'authenticated': hasattr(request, 'user') and request.user and request.user.is_authenticated,
			'user': request.user.username if hasattr(request, 'user') and request.user else None,
		}
	)


# Protected view (login required)
@login_required
def protected_view(request):
	"""View that requires authentication"""
	return JsonResponse(
		{
			'message': 'Welcome to the protected area!',
			'user': {
				'id': request.user.id,
				'username': request.user.username,
				'email': request.user.email,
				'roles': request.user.roles,
				'groups': request.user.groups,
			},
		}
	)


# Admin only view
@admin_required
def admin_view(request):
	"""View that requires admin role"""
	return JsonResponse(
		{
			'message': 'Welcome to the admin area!',
			'user': request.user.username,
			'admin_functions': ['User management', 'System configuration', 'Data export', 'Analytics'],
		}
	)


# Staff view
@staff_required
def staff_view(request):
	"""View that requires staff role"""
	return JsonResponse(
		{
			'message': 'Welcome to the staff area!',
			'user': request.user.username,
			'staff_functions': ['Content management', 'User support', 'Reports'],
		}
	)


# Role-specific view
@role_required(['manager', 'admin'])
def manager_view(request):
	"""View that requires manager or admin role"""
	return JsonResponse(
		{
			'message': 'Welcome to the management area!',
			'user': request.user.username,
			'roles': request.user.roles,
			'management_functions': ['Team management', 'Project oversight', 'Budget approval'],
		}
	)


# API endpoint with token requirement
@token_required
@require_http_methods(['GET'])
def api_user_profile(request):
	"""API endpoint that requires Bearer token"""
	return JsonResponse(
		{
			'user_profile': {
				'id': request.user.id,
				'username': request.user.username,
				'email': request.user.email,
				'first_name': request.user.first_name,
				'last_name': request.user.last_name,
				'full_name': request.user.get_full_name(),
				'roles': request.user.roles,
				'groups': request.user.groups,
				'is_staff': request.user.is_staff,
				'is_superuser': request.user.is_superuser,
				'token_expires_at': request.user.get_token_expiry_time(),
				'token_remaining_seconds': request.user.get_token_remaining_time(),
			},
			'permissions': list(request.user.get_all_permissions()),
		}
	)


# Class-based view example
class DashboardView(View):
	"""Dashboard view with authentication"""

	def dispatch(self, request, *args, **kwargs):
		# Check authentication
		if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
			return HttpResponse("""
            <!DOCTYPE html>
            <html>
            <head><title>Login Required</title></head>
            <body>
                <h1>Login Required</h1>
                <p><a href="/auth/login/">Please login to continue</a></p>
            </body>
            </html>
            """)

		return super().dispatch(request, *args, **kwargs)

	def get(self, request):
		"""Dashboard GET handler"""
		return HttpResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - {request.user.username}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .user-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .roles {{ color: #007bff; }}
                .logout-btn {{ background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Dashboard</h1>
            <div class="user-card">
                <h2>Welcome, {request.user.get_full_name() or request.user.username}!</h2>
                <p><strong>Email:</strong> {request.user.email}</p>
                <p><strong>Roles:</strong> <span class="roles">{', '.join(request.user.roles)}</span></p>
                <p><strong>Groups:</strong> {', '.join(request.user.groups)}</p>
                <p><strong>Token expires in:</strong> {request.user.get_token_remaining_time()} seconds</p>
            </div>
            
            <h3>Available Actions:</h3>
            <ul>
                <li><a href="/protected/">Protected Area</a></li>
                {'<li><a href="/admin-area/">Admin Area</a></li>' if request.user.has_role('admin') else ''}
                {'<li><a href="/staff-area/">Staff Area</a></li>' if request.user.has_role('staff') else ''}
                <li><a href="/auth/user-info/">User Info (JSON)</a></li>
                <li><a href="/auth/status/">Auth Status (JSON)</a></li>
            </ul>
            
            <p><a href="/auth/logout/" class="logout-btn">Logout</a></p>
        </body>
        </html>
        """)


# Multiple role requirement example
@role_required(['admin', 'manager'], require_all=False)  # User needs admin OR manager
def admin_or_manager_view(request):
	"""View accessible to admins or managers"""
	return JsonResponse(
		{
			'message': 'You have administrative or management privileges',
			'user': request.user.username,
			'roles': request.user.roles,
		}
	)


@role_required(['admin', 'auditor'], require_all=True)  # User needs BOTH admin AND auditor
def admin_auditor_view(request):
	"""View that requires both admin and auditor roles"""
	return JsonResponse(
		{
			'message': 'You have both admin and auditor privileges',
			'user': request.user.username,
			'roles': request.user.roles,
			'sensitive_data': 'This requires dual authorization',
		}
	)
