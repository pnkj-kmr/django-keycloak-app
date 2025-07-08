# app/user_keycloak/authentication.py
"""
Django REST Framework authentication classes for Keycloak
"""

import logging
from typing import Optional, Tuple
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .user import KeycloakUser
from .validators_pyjwt import jwt_validator
from .exceptions import TokenValidationError, TokenExpiredError, InvalidTokenError, TokenBlacklistedError
from .redis_util import redis_manager
from .utils import log_auth_event

logger = logging.getLogger('keycloak_auth')


class KeycloakAuthentication(BaseAuthentication):
	"""
	DRF authentication class for Keycloak JWT tokens
	"""

	keyword = 'Bearer'

	def authenticate(self, request) -> Optional[Tuple[KeycloakUser, str]]:
		"""
		Authenticate the request and return a two-tuple of (user, token).
		"""
		auth_header = self.get_authorization_header(request)
		if not auth_header or not auth_header.startswith(self.keyword.encode()):
			return None

		try:
			# Extract token
			token = auth_header.decode('utf-8').split(' ', 1)[1]

			# Validate token and create user
			user = self.authenticate_credentials(token)

			log_auth_event('drf_authentication_success', user_id=user.id)
			return (user, token)

		except (IndexError, UnicodeDecodeError):
			raise AuthenticationFailed('Invalid token header format')
		except AuthenticationFailed:
			raise
		except Exception as e:
			logger.error(f'Authentication error: {str(e)}')
			raise AuthenticationFailed('Authentication failed')

	def authenticate_credentials(self, token: str) -> KeycloakUser:
		"""
		Authenticate the token and return the user
		"""
		try:
			# Validate token and create user
			user = KeycloakUser.from_access_token(token)

			# Cache user data for performance
			redis_manager.store_user_tokens(user.id, user.tokens, user.get_token_remaining_time())
			redis_manager.cache_user_info(user.id, user.user_info, 300)

			return user

		except TokenExpiredError:
			raise AuthenticationFailed('Token has expired')
		except TokenBlacklistedError:
			raise AuthenticationFailed('Token has been revoked')
		except (TokenValidationError, InvalidTokenError) as e:
			raise AuthenticationFailed(f'Invalid token: {str(e)}')
		except Exception as e:
			logger.error(f'Token validation error: {str(e)}')
			raise AuthenticationFailed('Token validation failed')

	def get_authorization_header(self, request):
		"""
		Return the authorization header from the request
		"""
		auth = request.META.get('HTTP_AUTHORIZATION')
		if auth:
			return auth.encode('iso-8859-1')
		return None

	def authenticate_header(self, request):
		"""
		Return a string to be used as the value of the WWW-Authenticate
		header in a 401 Unauthenticated response.
		"""
		return f'{self.keyword} realm="api"'


class KeycloakSessionAuthentication(BaseAuthentication):
	"""
	Session-based authentication for DRF using Keycloak
	"""

	def authenticate(self, request) -> Optional[Tuple[KeycloakUser, None]]:
		"""
		Authenticate using session data
		"""
		user_id = request.session.get('user_id')
		if not user_id or not request.session.get('authenticated'):
			return None

		try:
			# Get user data from Redis
			user_tokens = redis_manager.get_user_tokens(user_id)
			user_info = redis_manager.get_cached_user_info(user_id)

			if not user_tokens or not user_info:
				return None

			# Create user object
			user = KeycloakUser(user_id, user_tokens, user_info)

			# Check if token is expired
			if user.is_token_expired():
				return None

			return (user, None)

		except Exception as e:
			logger.error(f'Session authentication error: {str(e)}')
			return None
