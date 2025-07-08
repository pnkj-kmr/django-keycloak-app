# app/user_keycloak/context_processors.py
"""
Template context processors for Keycloak authentication
"""

from django.conf import settings


def keycloak_auth(request):
	"""
	Add Keycloak authentication context to templates
	"""
	context = {
		'keycloak_user': None,
		'is_authenticated': False,
		'login_url': '/auth/login/',
		'logout_url': '/auth/logout/',
		'auth_status_url': '/auth/status/',
	}

	if hasattr(request, 'user') and request.user and request.user.is_authenticated:
		context.update(
			{
				'keycloak_user': request.user,
				'is_authenticated': True,
				'user_roles': request.user.roles,
				'user_groups': request.user.groups,
				'user_permissions': list(request.user.get_all_permissions()),
				'token_expires_at': request.user.get_token_expiry_time(),
				'token_remaining_seconds': request.user.get_token_remaining_time(),
			}
		)

	return context
