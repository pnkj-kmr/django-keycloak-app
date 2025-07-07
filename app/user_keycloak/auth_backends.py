# app/user_keycloak/auth_backends.py
"""
Custom authentication backend for Keycloak integration - NO Django auth dependencies
"""

import logging
from typing import Optional, Any
from django.http import HttpRequest

from .redis_util import redis_manager
from .utils import log_auth_event

logger = logging.getLogger(__name__)


class KeycloakUser:
	"""
	Custom user class to replace Django's User model
	"""

	def __init__(self, user_id: str, tokens: dict, user_info: dict):
		self.id = user_id
		self.pk = user_id  # Primary key alias
		self.username = user_info.get('preferred_username', 'unknown')
		self.email = user_info.get('email', '')
		self.first_name = user_info.get('given_name', '')
		self.last_name = user_info.get('family_name', '')
		self.is_authenticated = True
		self.is_active = True
		self.is_anonymous = False
		self.is_superuser = False  # Set based on roles if needed
		self.is_staff = False  # Set based on roles if needed

		# Keycloak-specific attributes
		self.roles = user_info.get('roles', [])
		self.groups = user_info.get('groups', [])
		self.tokens = tokens
		self.user_info = user_info

		# Set staff/superuser based on roles
		self.is_staff = self.has_role('staff') or self.has_role('admin')
		self.is_superuser = self.has_role('admin') or self.has_role('superuser')

	def __str__(self):
		return self.username

	def __repr__(self):
		return f'<KeycloakUser: {self.username}>'

	def get_username(self):
		"""Return the username for this User."""
		return self.username

	def get_full_name(self):
		"""Return the first_name plus the last_name, with a space in between."""
		full_name = f'{self.first_name} {self.last_name}'.strip()
		return full_name if full_name else self.username

	def get_short_name(self):
		"""Return the short name for the user."""
		return self.first_name or self.username

	def has_role(self, role: str) -> bool:
		"""Check if user has a specific role"""
		return role in self.roles

	def has_any_role(self, roles: list) -> bool:
		"""Check if user has any of the specified roles"""
		return any(role in self.roles for role in roles)

	def has_all_roles(self, roles: list) -> bool:
		"""Check if user has all of the specified roles"""
		return all(role in self.roles for role in roles)

	def in_group(self, group: str) -> bool:
		"""Check if user is in a specific group"""
		return group in self.groups

	def get_access_token(self) -> str:
		"""Get the current access token"""
		return self.tokens.get('access_token', '')

	def get_refresh_token(self) -> str:
		"""Get the current refresh token"""
		return self.tokens.get('refresh_token', '')

	def is_token_expired(self) -> bool:
		"""Check if the access token is expired"""
		import time

		expires_at = self.tokens.get('expires_at', 0)
		return time.time() >= expires_at

	# Django-compatible permission methods (simplified for Keycloak)
	def has_perm(self, perm: str, obj=None) -> bool:
		"""
		Check if user has a specific permission
		For Keycloak, we base this on roles
		"""
		# Convert permission to role check
		# e.g., 'myapp.view_model' -> check for 'view_model' role
		if '.' in perm:
			app_label, perm_name = perm.split('.', 1)
			return self.has_role(perm_name) or self.has_role('admin')
		return self.has_role(perm) or self.has_role('admin')

	def has_perms(self, perm_list: list, obj=None) -> bool:
		"""Check if user has all specified permissions"""
		return all(self.has_perm(perm, obj) for perm in perm_list)

	def has_module_perms(self, app_label: str) -> bool:
		"""Check if user has permissions for an app"""
		# Check if user has admin role or any role related to the app
		return self.has_role('admin') or self.has_role(f'{app_label}_admin')

	def get_user_permissions(self, obj=None):
		"""Return a set of permission strings the user has"""
		# Convert roles to Django-style permissions
		permissions = set()
		for role in self.roles:
			permissions.add(f'keycloak.{role}')
		return permissions

	def get_group_permissions(self, obj=None):
		"""Return a set of permission strings the user has through groups"""
		# Convert groups to permissions
		permissions = set()
		for group in self.groups:
			permissions.add(f'group.{group}')
		return permissions

	def get_all_permissions(self, obj=None):
		"""Return a set of all permissions the user has"""
		return self.get_user_permissions(obj) | self.get_group_permissions(obj)


class KeycloakAuthenticationBackend:
	"""
	Custom authentication backend for Keycloak - NO Django auth inheritance
	"""

	def authenticate(
		self, request: HttpRequest, username: str = None, password: str = None, **kwargs
	) -> Optional[KeycloakUser]:
		"""
		Authenticate user against Keycloak

		Note: This method is typically called during the OAuth callback,
		not for every request. The middleware handles request authentication.
		"""
		# For Keycloak, we don't use username/password authentication
		# Instead, we rely on JWT tokens from the OAuth flow

		user_id = kwargs.get('user_id')
		if not user_id:
			return None

		try:
			# Get user data from Redis
			tokens = redis_manager.get_user_tokens(user_id)
			user_info = redis_manager.get_cached_user_info(user_id)

			if not tokens or not user_info:
				logger.warning(f'No cached data found for user {user_id}')
				return None

			# Create and return KeycloakUser
			user = KeycloakUser(user_id, tokens, user_info)

			log_auth_event('backend_authenticate_success', user_id=user_id)
			logger.debug(f'Successfully authenticated user {user_id} via backend')

			return user

		except Exception as e:
			log_auth_event('backend_authenticate_error', user_id=user_id, details={'error': str(e)})
			logger.error(f'Authentication backend error for user {user_id}: {str(e)}')
			return None

	def get_user(self, user_id: str) -> Optional[KeycloakUser]:
		"""
		Get user by ID (called by Django for session-based auth)
		"""
		try:
			# Get user data from Redis
			tokens = redis_manager.get_user_tokens(user_id)
			user_info = redis_manager.get_cached_user_info(user_id)

			if not tokens or not user_info:
				logger.debug(f'No cached data found for user {user_id}')
				return None

			# Check if token is expired
			import time

			expires_at = tokens.get('expires_at', 0)
			if time.time() >= expires_at:
				logger.debug(f'Token expired for user {user_id}')
				# Clean up expired data
				redis_manager.invalidate_user_tokens(user_id)
				return None

			# Create and return KeycloakUser
			user = KeycloakUser(user_id, tokens, user_info)

			logger.debug(f'Retrieved user {user_id} from backend')
			return user

		except Exception as e:
			logger.error(f'Error retrieving user {user_id}: {str(e)}')
			return None

	def user_can_authenticate(self, user: KeycloakUser) -> bool:
		"""
		Reject users with is_active=False. Custom user models that don't have
		an is_active field are allowed.
		"""
		return getattr(user, 'is_active', True)

	def has_perm(self, user_obj: KeycloakUser, perm: str, obj=None) -> bool:
		"""
		Check if user has permission
		"""
		if not user_obj or not user_obj.is_active:
			return False

		return user_obj.has_perm(perm, obj)

	def has_module_perms(self, user_obj: KeycloakUser, app_label: str) -> bool:
		"""
		Check if user has permissions for app
		"""
		if not user_obj or not user_obj.is_active:
			return False

		return user_obj.has_module_perms(app_label)

	def get_user_permissions(self, user_obj: KeycloakUser, obj=None):
		"""
		Return user permissions
		"""
		if not user_obj or not user_obj.is_active:
			return set()

		return user_obj.get_user_permissions(obj)

	def get_group_permissions(self, user_obj: KeycloakUser, obj=None):
		"""
		Return group permissions
		"""
		if not user_obj or not user_obj.is_active:
			return set()

		return user_obj.get_group_permissions(obj)

	def get_all_permissions(self, user_obj: KeycloakUser, obj=None):
		"""
		Return all permissions
		"""
		if not user_obj or not user_obj.is_active:
			return set()

		return user_obj.get_all_permissions(obj)


# For compatibility with Django's user system
def get_user_model():
	"""
	Return the KeycloakUser class as the user model
	"""
	return KeycloakUser
