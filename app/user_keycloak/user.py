# app/user_keycloak/keycloak/user.py
"""
Enhanced KeycloakUser class with real JWT validation
"""

import logging
import time
from typing import Dict, Any, Optional

# from .validators import jwt_validator
from .validators_pyjwt import jwt_validator
from .redis_util import redis_manager
from .exceptions import TokenValidationError, TokenExpiredError

logger = logging.getLogger('keycloak_auth')


class KeycloakUser:
	"""
	Enhanced user class with real JWT token validation
	"""

	def __init__(self, user_id: str, tokens: Dict[str, Any], user_info: Dict[str, Any]):
		# Basic user attributes
		self.id = user_id
		self.pk = user_id
		self.username = user_info.get('preferred_username', 'unknown')
		self.email = user_info.get('email', '')
		self.first_name = user_info.get('given_name', '')
		self.last_name = user_info.get('family_name', '')
		self.full_name = user_info.get('name', '')

		# Authentication state
		self.is_authenticated = True
		self.is_active = True
		self.is_anonymous = False

		# Keycloak-specific attributes
		self.roles = user_info.get('roles', [])
		self.groups = user_info.get('groups', [])
		self.tokens = tokens
		self.user_info = user_info

		# JWT-specific attributes
		self.jti = user_info.get('jti')  # JWT ID
		self.iat = user_info.get('iat')  # Issued at
		self.exp = user_info.get('exp')  # Expires at
		self.email_verified = user_info.get('email_verified', False)

		# Set staff/superuser based on roles
		self.is_staff = self.has_role('staff') or self.has_role('admin')
		self.is_superuser = self.has_role('admin') or self.has_role('superuser')

		logger.debug(f'Created KeycloakUser: {self.username} with roles: {self.roles}')

	@classmethod
	def from_access_token(cls, access_token: str) -> 'KeycloakUser':
		"""
		Create KeycloakUser from access token by validating and extracting info

		Args:
		    access_token: JWT access token

		Returns:
		    KeycloakUser instance

		Raises:
		    TokenValidationError: If token validation fails
		"""
		try:
			# Validate token and extract user info
			payload, user_info = jwt_validator.validate_and_extract(access_token)

			# Create tokens dict
			tokens = {
				'access_token': access_token,
				'token_type': 'Bearer',
				'expires_at': payload.get('exp', 0),
				'issued_at': payload.get('iat', 0),
			}

			user_id = user_info['sub']
			return cls(user_id, tokens, user_info)

		except Exception as e:
			logger.error(f'Failed to create user from token: {str(e)}')
			raise TokenValidationError(f'Cannot create user from token: {str(e)}')

	def __str__(self):
		return self.username

	def __repr__(self):
		return f'<KeycloakUser: {self.username} (roles: {", ".join(self.roles)})>'

	def get_username(self):
		"""Return the username for this User."""
		return self.username

	def get_full_name(self):
		"""Return the full name or construct from first/last name."""
		if self.full_name:
			return self.full_name

		full_name = f'{self.first_name} {self.last_name}'.strip()
		return full_name if full_name else self.username

	def get_short_name(self):
		"""Return the short name for the user."""
		return self.first_name or self.username

	# Role and permission methods
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

	# Token methods
	def get_access_token(self) -> str:
		"""Get the current access token"""
		return self.tokens.get('access_token', '')

	def get_refresh_token(self) -> str:
		"""Get the current refresh token"""
		return self.tokens.get('refresh_token', '')

	def is_token_expired(self) -> bool:
		"""Check if the access token is expired"""
		expires_at = self.tokens.get('expires_at', self.exp)
		if expires_at:
			return time.time() >= expires_at
		return False

	def get_token_expiry_time(self) -> Optional[int]:
		"""Get token expiry timestamp"""
		return self.tokens.get('expires_at', self.exp)

	def get_token_remaining_time(self) -> int:
		"""Get remaining time in seconds before token expires"""
		expires_at = self.get_token_expiry_time()
		if expires_at:
			remaining = expires_at - time.time()
			return max(0, int(remaining))
		return 0

	def refresh_token_if_needed(self, threshold_seconds: int = 300) -> bool:
		"""
		Refresh token if it expires within threshold_seconds

		Args:
		    threshold_seconds: Refresh if token expires within this time

		Returns:
		    True if token was refreshed, False otherwise
		"""
		try:
			remaining = self.get_token_remaining_time()
			if remaining <= threshold_seconds:
				logger.info(f'Token expires in {remaining}s, refreshing for user {self.id}')

				from .client import keycloak_client

				refresh_token = self.get_refresh_token()
				if not refresh_token:
					logger.warning(f'No refresh token available for user {self.id}')
					return False

				# Refresh tokens
				new_tokens = keycloak_client.refresh_access_token(refresh_token)

				# Update stored tokens
				self.tokens.update(new_tokens)

				# Update Redis cache
				redis_manager.update_user_tokens(self.id, self.tokens, new_tokens.get('expires_in', 3600))

				logger.info(f'Successfully refreshed token for user {self.id}')
				return True

			return False

		except Exception as e:
			logger.error(f'Failed to refresh token for user {self.id}: {str(e)}')
			return False

	# Django-compatible permission methods
	def has_perm(self, perm: str, obj=None) -> bool:
		"""
		Check if user has a specific permission
		Maps Django permissions to Keycloak roles
		"""
		if not self.is_active:
			return False

		# Admin users have all permissions
		if self.has_role('admin') or self.has_role('superuser'):
			return True

		# Convert permission to role check
		if '.' in perm:
			app_label, perm_name = perm.split('.', 1)
			# Check for specific permission role or app admin role
			return (
				self.has_role(perm_name)
				or self.has_role(f'{app_label}_{perm_name}')
				or self.has_role(f'{app_label}_admin')
			)

		return self.has_role(perm)

	def has_perms(self, perm_list: list, obj=None) -> bool:
		"""Check if user has all specified permissions"""
		return all(self.has_perm(perm, obj) for perm in perm_list)

	def has_module_perms(self, app_label: str) -> bool:
		"""Check if user has permissions for an app"""
		if not self.is_active:
			return False

		return self.has_role('admin') or self.has_role('superuser') or self.has_role(f'{app_label}_admin')

	def get_user_permissions(self, obj=None):
		"""Return a set of permission strings the user has"""
		permissions = set()
		for role in self.roles:
			permissions.add(f'keycloak.{role}')
		return permissions

	def get_group_permissions(self, obj=None):
		"""Return a set of permission strings from groups"""
		permissions = set()
		for group in self.groups:
			permissions.add(f'group.{group}')
		return permissions

	def get_all_permissions(self, obj=None):
		"""Return all permissions the user has"""
		return self.get_user_permissions(obj) | self.get_group_permissions(obj)

	# Utility methods
	def to_dict(self) -> Dict[str, Any]:
		"""Convert user to dictionary representation"""
		return {
			'id': self.id,
			'username': self.username,
			'email': self.email,
			'first_name': self.first_name,
			'last_name': self.last_name,
			'full_name': self.get_full_name(),
			'roles': self.roles,
			'groups': self.groups,
			'is_staff': self.is_staff,
			'is_superuser': self.is_superuser,
			'is_authenticated': self.is_authenticated,
			'is_active': self.is_active,
			'email_verified': self.email_verified,
			'token_expires_at': self.get_token_expiry_time(),
			'token_remaining_seconds': self.get_token_remaining_time(),
		}
