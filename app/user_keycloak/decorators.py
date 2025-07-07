# app/user_keycloak/decorators.py
"""
Permission decorators for Keycloak authentication
"""

import logging
from functools import wraps
from typing import List, Union, Callable
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

from .utils import log_auth_event

logger = logging.getLogger('keycloak_auth')


def login_required(view_func: Callable = None, *, redirect_url: str = None):
	"""
	Decorator that requires user to be authenticated

	Args:
	    view_func: The view function to decorate
	    redirect_url: Custom redirect URL for unauthenticated users
	"""

	def decorator(func):
		@wraps(func)
		def wrapper(request, *args, **kwargs):
			if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
				log_auth_event('login_required_failed', details={'path': request.path, 'view': func.__name__})

				# Check if it's an API request
				if request.path.startswith('/api/') or request.META.get('HTTP_ACCEPT', '').startswith(
					'application/json'
				):
					return JsonResponse(
						{
							'error': 'Authentication required',
							'error_code': 'LOGIN_REQUIRED',
							'login_url': '/auth/login/',
						},
						status=401,
					)

				# Web request - redirect to login
				login_url = redirect_url or '/auth/login/'
				next_url = f'{login_url}?next={request.path}'
				return redirect(next_url)

			return func(request, *args, **kwargs)

		return wrapper

	if view_func:
		return decorator(view_func)
	return decorator


def role_required(roles: Union[str, List[str]], require_all: bool = False):
	"""
	Decorator that requires user to have specific role(s)

	Args:
	    roles: Single role string or list of roles
	    require_all: If True, user must have ALL roles. If False, user needs ANY role.
	"""
	if isinstance(roles, str):
		roles = [roles]

	def decorator(view_func):
		@wraps(view_func)
		def wrapper(request, *args, **kwargs):
			# First check if user is authenticated
			if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
				return redirect('/auth/login/')

			# Check roles
			user_roles = request.user.roles

			if require_all:
				has_permission = all(role in user_roles for role in roles)
				check_type = 'all'
			else:
				has_permission = any(role in user_roles for role in roles)
				check_type = 'any'

			if not has_permission:
				log_auth_event(
					'role_required_failed',
					user_id=request.user.id,
					details={
						'path': request.path,
						'view': view_func.__name__,
						'required_roles': roles,
						'user_roles': user_roles,
						'check_type': check_type,
					},
				)

				# Check if it's an API request
				if request.path.startswith('/api/') or request.META.get('HTTP_ACCEPT', '').startswith(
					'application/json'
				):
					return JsonResponse(
						{
							'error': 'Insufficient permissions',
							'error_code': 'ROLE_REQUIRED',
							'required_roles': roles,
							'your_roles': user_roles,
							'require_all': require_all,
						},
						status=403,
					)

				# Web request - show forbidden page
				return HttpResponseForbidden(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Access Denied</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 50px; text-align: center; }}
                        .error-container {{ max-width: 500px; margin: 0 auto; }}
                        .back-btn {{ 
                            background: #6c757d; color: white; padding: 10px 20px; 
                            text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;
                        }}
                    </style>
                </head>
                <body>
                    <div class="error-container">
                        <h1>🚫 Access Denied</h1>
                        <p>You don't have permission to access this resource.</p>
                        <p><strong>Required roles:</strong> {', '.join(roles)}</p>
                        <p><strong>Your roles:</strong> {', '.join(user_roles)}</p>
                        <p><strong>Check type:</strong> {check_type.upper()}</p>
                        <a href="/" class="back-btn">Go Home</a>
                    </div>
                </body>
                </html>
                """)

			return view_func(request, *args, **kwargs)

		return wrapper

	return decorator


def admin_required(view_func: Callable = None):
	"""
	Decorator that requires user to have admin role
	"""

	def decorator(func):
		return role_required(['admin', 'superuser'])(func)

	if view_func:
		return decorator(view_func)
	return decorator


def staff_required(view_func: Callable = None):
	"""
	Decorator that requires user to have staff role
	"""

	def decorator(func):
		return role_required(['staff', 'admin', 'superuser'])(func)

	if view_func:
		return decorator(view_func)
	return decorator


def group_required(groups: Union[str, List[str]], require_all: bool = False):
	"""
	Decorator that requires user to be in specific group(s)

	Args:
	    groups: Single group string or list of groups
	    require_all: If True, user must be in ALL groups. If False, user needs ANY group.
	"""
	if isinstance(groups, str):
		groups = [groups]

	def decorator(view_func):
		@wraps(view_func)
		def wrapper(request, *args, **kwargs):
			# First check if user is authenticated
			if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
				return redirect('/auth/login/')

			# Check groups
			user_groups = request.user.groups

			if require_all:
				has_permission = all(group in user_groups for group in groups)
			else:
				has_permission = any(group in user_groups for group in groups)

			if not has_permission:
				log_auth_event(
					'group_required_failed',
					user_id=request.user.id,
					details={
						'path': request.path,
						'view': view_func.__name__,
						'required_groups': groups,
						'user_groups': user_groups,
					},
				)

				if request.path.startswith('/api/'):
					return JsonResponse(
						{
							'error': 'Insufficient permissions',
							'error_code': 'GROUP_REQUIRED',
							'required_groups': groups,
							'your_groups': user_groups,
						},
						status=403,
					)

				return HttpResponseForbidden('Access denied: insufficient group permissions')

			return view_func(request, *args, **kwargs)

		return wrapper

	return decorator


def permission_required(permission: str):
	"""
	Decorator that requires user to have specific Django-style permission

	Args:
	    permission: Permission string (e.g., 'myapp.view_model')
	"""

	def decorator(view_func):
		@wraps(view_func)
		def wrapper(request, *args, **kwargs):
			if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
				return redirect('/auth/login/')

			if not request.user.has_perm(permission):
				log_auth_event(
					'permission_required_failed',
					user_id=request.user.id,
					details={
						'path': request.path,
						'view': view_func.__name__,
						'required_permission': permission,
						'user_permissions': list(request.user.get_all_permissions()),
					},
				)

				if request.path.startswith('/api/'):
					return JsonResponse(
						{
							'error': 'Insufficient permissions',
							'error_code': 'PERMISSION_REQUIRED',
							'required_permission': permission,
						},
						status=403,
					)

				return HttpResponseForbidden(f'Access denied: {permission} permission required')

			return view_func(request, *args, **kwargs)

		return wrapper

	return decorator


def token_required(view_func: Callable = None):
	"""
	Decorator that requires a valid access token (for API views)
	"""

	def decorator(func):
		@wraps(func)
		def wrapper(request, *args, **kwargs):
			# Check for Authorization header
			auth_header = request.META.get('HTTP_AUTHORIZATION', '')
			if not auth_header.startswith('Bearer '):
				return JsonResponse(
					{
						'error': 'Authorization header required',
						'error_code': 'TOKEN_REQUIRED',
						'details': 'Please provide Authorization: Bearer <token> header',
					},
					status=401,
				)

			# Check if user was authenticated by middleware
			if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
				return JsonResponse({'error': 'Invalid or expired token', 'error_code': 'TOKEN_INVALID'}, status=401)

			return func(request, *args, **kwargs)

		return wrapper

	if view_func:
		return decorator(view_func)
	return decorator


class ConditionalPermissionMixin:
	"""
	Mixin for class-based views that provides conditional permission checking
	"""

	def check_permissions(self, request):
		"""
		Override this method in your view to implement custom permission logic
		Return True if permission granted, False otherwise
		"""
		return True

	def dispatch(self, request, *args, **kwargs):
		if not self.check_permissions(request):
			if request.path.startswith('/api/'):
				return JsonResponse({'error': 'Permission denied', 'error_code': 'PERMISSION_DENIED'}, status=403)
			return HttpResponseForbidden('Permission denied')

		return super().dispatch(request, *args, **kwargs)


# Utility functions for permission checking
def check_user_permission(user, permission: str) -> bool:
	"""
	Check if a user has a specific permission

	Args:
	    user: KeycloakUser instance
	    permission: Permission string

	Returns:
	    True if user has permission, False otherwise
	"""
	if not user or not user.is_authenticated:
		return False

	return user.has_perm(permission)


def check_user_role(user, roles: Union[str, List[str]], require_all: bool = False) -> bool:
	"""
	Check if a user has specific role(s)

	Args:
	    user: KeycloakUser instance
	    roles: Single role or list of roles
	    require_all: Whether user needs all roles or just any

	Returns:
	    True if user has required roles, False otherwise
	"""
	if not user or not user.is_authenticated:
		return False

	if isinstance(roles, str):
		roles = [roles]

	if require_all:
		return user.has_all_roles(roles)
	else:
		return user.has_any_role(roles)
