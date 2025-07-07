"""
Custom exceptions for Keycloak integration with Redis context
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class KeycloakAuthenticationError(Exception):
	"""Base exception for Keycloak authentication errors"""

	def __init__(self, message: str, user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
		super().__init__(message)
		self.user_id = user_id
		self.details = details or {}

		# Log the error
		logger.error(f'KeycloakAuthenticationError: {message}', extra={'user_id': user_id, 'details': details})


class TokenValidationError(KeycloakAuthenticationError):
	"""Raised when JWT token validation fails"""

	pass


class TokenExpiredError(TokenValidationError):
	"""Raised when JWT token has expired"""

	def __init__(self, message: str = 'Token has expired', **kwargs):
		super().__init__(message, **kwargs)


class InvalidTokenError(TokenValidationError):
	"""Raised when JWT token is invalid or malformed"""

	def __init__(self, message: str = 'Invalid token', **kwargs):
		super().__init__(message, **kwargs)


class TokenBlacklistedError(TokenValidationError):
	"""Raised when JWT token is blacklisted"""

	def __init__(self, message: str = 'Token has been revoked', **kwargs):
		super().__init__(message, **kwargs)


class KeycloakConnectionError(KeycloakAuthenticationError):
	"""Raised when connection to Keycloak server fails"""

	def __init__(self, message: str = 'Cannot connect to Keycloak server', **kwargs):
		super().__init__(message, **kwargs)


class UserNotFoundError(KeycloakAuthenticationError):
	"""Raised when user is not found in Keycloak"""

	def __init__(self, message: str = 'User not found', **kwargs):
		super().__init__(message, **kwargs)


class InsufficientPermissionsError(KeycloakAuthenticationError):
	"""Raised when user lacks required permissions"""

	def __init__(self, message: str = 'Insufficient permissions', required_roles: Optional[list] = None, **kwargs):
		super().__init__(message, **kwargs)
		self.required_roles = required_roles or []


class TokenRefreshError(KeycloakAuthenticationError):
	"""Raised when token refresh fails"""

	def __init__(self, message: str = 'Token refresh failed', **kwargs):
		super().__init__(message, **kwargs)


class RedisConnectionError(KeycloakAuthenticationError):
	"""Raised when Redis connection fails"""

	def __init__(self, message: str = 'Redis connection failed', **kwargs):
		super().__init__(message, **kwargs)


class SessionExpiredError(KeycloakAuthenticationError):
	"""Raised when user session has expired"""

	def __init__(self, message: str = 'Session has expired', **kwargs):
		super().__init__(message, **kwargs)


class OAuthStateError(KeycloakAuthenticationError):
	"""Raised when OAuth state validation fails"""

	def __init__(self, message: str = 'Invalid OAuth state', **kwargs):
		super().__init__(message, **kwargs)
