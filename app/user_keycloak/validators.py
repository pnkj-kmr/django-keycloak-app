# app/user_keycloak/keycloak/validators.py
"""
JWT token validation for Keycloak integration
"""

import json
import logging
import requests
import time
from typing import Dict, Any, Optional
from jose import jwt, jwk, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
from django.conf import settings
from django.core.cache import cache

from .exceptions import (
	TokenValidationError,
	TokenExpiredError,
	InvalidTokenError,
	KeycloakConnectionError,
	TokenBlacklistedError,
)
from .redis_util import redis_manager

logger = logging.getLogger('keycloak_auth')


class KeycloakJWTValidator:
	"""
	Validates JWT tokens from Keycloak
	"""

	def __init__(self):
		self.keycloak_config = getattr(settings, 'KEYCLOAK_CONFIG', {})
		self.jwks_url = self.keycloak_config.get('JWKS_URL')
		self.issuer = self.keycloak_config.get('ISSUER')
		self.audience = self.keycloak_config.get('AUDIENCE')
		self.algorithms = self.keycloak_config.get('ALGORITHMS', ['RS256'])
		self.leeway = self.keycloak_config.get('LEEWAY', 10)

	def get_public_keys(self) -> Dict[str, Any]:
		"""
		Fetch public keys from Keycloak JWKS endpoint with caching

		Returns:
		    JWKS dictionary containing public keys
		"""
		try:
			# Try to get from cache first
			cached_jwks = redis_manager.get_cached_keycloak_jwks()
			if cached_jwks:
				logger.debug('Using cached JWKS')
				return cached_jwks

			# Fetch from Keycloak
			logger.debug(f'Fetching JWKS from {self.jwks_url}')
			response = requests.get(self.jwks_url, timeout=10, headers={'Accept': 'application/json'})
			response.raise_for_status()

			jwks = response.json()

			# Cache the JWKS
			cache_timeout = self.keycloak_config.get('JWKS_CACHE_TIMEOUT', 3600)
			redis_manager.cache_keycloak_jwks(jwks, cache_timeout)

			logger.debug('Successfully fetched and cached JWKS')
			return jwks

		except requests.RequestException as e:
			logger.error(f'Failed to fetch JWKS: {str(e)}')
			raise KeycloakConnectionError(f'Cannot fetch public keys: {str(e)}')
		except Exception as e:
			logger.error(f'Unexpected error fetching JWKS: {str(e)}')
			raise TokenValidationError(f'Error fetching public keys: {str(e)}')

	def get_signing_key(self, token_header: Dict[str, Any]) -> Any:
		"""
		Get the signing key for token validation

		Args:
		    token_header: JWT token header containing 'kid'

		Returns:
		    Signing key object
		"""
		kid = token_header.get('kid')
		if not kid:
			raise InvalidTokenError("Token header missing 'kid' (key ID)")

		jwks = self.get_public_keys()

		# Find the key with matching kid
		for key_data in jwks.get('keys', []):
			if key_data.get('kid') == kid:
				try:
					# Construct the key
					key = jwk.construct(key_data)
					logger.debug(f'Found signing key for kid: {kid}')
					return key
				except Exception as e:
					logger.error(f'Error constructing key for kid {kid}: {str(e)}')
					raise InvalidTokenError(f'Invalid key data for kid {kid}')

		raise InvalidTokenError(f'No key found for kid: {kid}')

	def validate_token(self, token: str) -> Dict[str, Any]:
		"""
		Validate JWT token and return payload

		Args:
		    token: JWT token string

		Returns:
		    Token payload dictionary

		Raises:
		    TokenValidationError: If token validation fails
		    TokenExpiredError: If token has expired
		    InvalidTokenError: If token is malformed
		    TokenBlacklistedError: If token is blacklisted
		"""
		try:
			# Decode header without verification to get key ID
			header = jwt.get_unverified_header(token)
			logger.debug(f'Token header: {header}')

			# Get signing key
			signing_key = self.get_signing_key(header)

			# Validate and decode token
			payload = jwt.decode(
				token,
				signing_key,
				algorithms=self.algorithms,
				audience=self.audience,
				issuer=self.issuer,
				options={
					'verify_signature': True,
					'verify_exp': True,
					'verify_iat': True,
					'verify_aud': True,
					'verify_iss': True,
					'require_exp': True,
					'require_iat': True,
				},
				leeway=self.leeway,
			)

			# Check if token is blacklisted
			jti = payload.get('jti')
			if jti and redis_manager.is_jwt_blacklisted(jti):
				raise TokenBlacklistedError(f'Token {jti} is blacklisted')

			logger.debug(f'Token validated successfully for user: {payload.get("sub")}')
			return payload

		except ExpiredSignatureError:
			logger.warning('Token has expired')
			raise TokenExpiredError('Token has expired')

		except JWTClaimsError as e:
			logger.warning(f'JWT claims validation failed: {str(e)}')
			raise InvalidTokenError(f'Invalid token claims: {str(e)}')

		except JWTError as e:
			logger.warning(f'JWT validation failed: {str(e)}')
			raise InvalidTokenError(f'Invalid token: {str(e)}')

		except Exception as e:
			logger.error(f'Unexpected error validating token: {str(e)}')
			raise TokenValidationError(f'Token validation error: {str(e)}')

	def extract_user_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		"""
		Extract user information from JWT payload

		Args:
		    payload: JWT token payload

		Returns:
		    User information dictionary
		"""
		user_info = {
			'sub': payload.get('sub'),
			'preferred_username': payload.get('preferred_username'),
			'email': payload.get('email'),
			'email_verified': payload.get('email_verified', False),
			'given_name': payload.get('given_name', ''),
			'family_name': payload.get('family_name', ''),
			'name': payload.get('name', ''),
			'roles': [],
			'groups': payload.get('groups', []),
			'iat': payload.get('iat'),
			'exp': payload.get('exp'),
			'jti': payload.get('jti'),
		}

		# Extract realm roles
		realm_access = payload.get('realm_access', {})
		if isinstance(realm_access, dict):
			user_info['roles'].extend(realm_access.get('roles', []))

		# Extract client roles
		resource_access = payload.get('resource_access', {})
		client_id = self.keycloak_config.get('CLIENT_ID', '')
		if client_id in resource_access:
			client_roles = resource_access[client_id].get('roles', [])
			user_info['roles'].extend(client_roles)

		# Remove duplicates
		user_info['roles'] = list(set(user_info['roles']))

		logger.debug(f'Extracted user info for {user_info["sub"]}: {user_info["preferred_username"]}')
		return user_info

	def validate_and_extract(self, token: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
		"""
		Validate token and extract user information in one call

		Args:
		    token: JWT token string

		Returns:
		    Tuple of (payload, user_info)
		"""
		payload = self.validate_token(token)
		user_info = self.extract_user_info(payload)
		return payload, user_info


# Global validator instance
jwt_validator = KeycloakJWTValidator()
