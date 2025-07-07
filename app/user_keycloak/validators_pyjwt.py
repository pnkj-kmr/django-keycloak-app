# app/user_keycloak/keycloak/validators.py
"""
JWT token validation using PyJWT - Production Ready
"""

import jwt
import json
import logging
import requests
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
import base64

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
	Production-ready JWT validator using PyJWT for Keycloak
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
		Fetch and cache Keycloak's public keys
		"""
		try:
			# Try cache first
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

	def jwk_to_pem(self, jwk_data: Dict[str, Any]) -> bytes:
		"""
		Convert JWK to PEM format for PyJWT
		Handles RSA keys from Keycloak
		"""
		try:
			if jwk_data.get('kty') != 'RSA':
				raise ValueError(f'Unsupported key type: {jwk_data.get("kty")}')

			# Helper function for base64url decoding
			def base64url_decode(data: str) -> bytes:
				# Add padding if needed
				padding = 4 - (len(data) % 4)
				if padding != 4:
					data += '=' * padding
				return base64.urlsafe_b64decode(data)

			# Extract modulus and exponent
			n = int.from_bytes(base64url_decode(jwk_data['n']), 'big')
			e = int.from_bytes(base64url_decode(jwk_data['e']), 'big')

			# Create RSA public key
			public_key = rsa.RSAPublicNumbers(e, n).public_key()

			# Convert to PEM format
			pem = public_key.public_bytes(
				encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
			)

			return pem

		except Exception as e:
			logger.error(f'Failed to convert JWK to PEM: {str(e)}')
			raise InvalidTokenError(f'Invalid key format: {str(e)}')

	def get_signing_key(self, token_header: Dict[str, Any]) -> bytes:
		"""
		Get the signing key for token validation
		"""
		kid = token_header.get('kid')
		if not kid:
			raise InvalidTokenError("Token header missing 'kid' (key ID)")

		jwks = self.get_public_keys()

		# Find the key with matching kid
		for key_data in jwks.get('keys', []):
			if key_data.get('kid') == kid:
				try:
					pem_key = self.jwk_to_pem(key_data)
					logger.debug(f'Found and converted signing key for kid: {kid}')
					return pem_key
				except Exception as e:
					logger.error(f'Error converting key for kid {kid}: {str(e)}')
					raise InvalidTokenError(f'Invalid key data for kid {kid}')

		raise InvalidTokenError(f'No key found for kid: {kid}')

	def validate_token(self, token: str) -> Dict[str, Any]:
		"""
		Validate JWT token using PyJWT
		"""
		try:
			# Get header to find the right key
			header = jwt.get_unverified_header(token)
			logger.debug(f'Token header: {header}')

			# Get signing key
			signing_key = self.get_signing_key(header)

			# Prepare decode options
			options = {
				'verify_signature': True,
				'verify_exp': True,
				'verify_iat': True,
				'verify_aud': bool(self.audience),
				'verify_iss': bool(self.issuer),
				'require_exp': True,
				'require_iat': True,
			}

			# Prepare decode parameters
			decode_params = {
				'jwt': token,
				'key': signing_key,
				'algorithms': self.algorithms,
				'options': options,
				'leeway': self.leeway,  # PyJWT handles this properly
			}

			# Add audience and issuer if configured
			if self.audience:
				decode_params['audience'] = self.audience
			if self.issuer:
				decode_params['issuer'] = self.issuer

			# Decode and validate token
			payload = jwt.decode(**decode_params)

			# Check if token is blacklisted
			jti = payload.get('jti')
			if jti and redis_manager.is_jwt_blacklisted(jti):
				raise TokenBlacklistedError(f'Token {jti} is blacklisted')

			logger.debug(f'Token validated successfully for user: {payload.get("sub")}')
			return payload

		except jwt.ExpiredSignatureError:
			logger.warning('Token has expired')
			raise TokenExpiredError('Token has expired')

		except jwt.InvalidAudienceError as e:
			logger.warning(f'Invalid audience: {str(e)}')
			raise InvalidTokenError(f'Invalid audience: {str(e)}')

		except jwt.InvalidIssuerError as e:
			logger.warning(f'Invalid issuer: {str(e)}')
			raise InvalidTokenError(f'Invalid issuer: {str(e)}')

		except jwt.InvalidTokenError as e:
			logger.warning(f'Invalid token: {str(e)}')
			raise InvalidTokenError(f'Invalid token: {str(e)}')

		except Exception as e:
			logger.error(f'Unexpected error validating token: {str(e)}')
			raise TokenValidationError(f'Token validation error: {str(e)}')

	def extract_user_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		"""
		Extract user information from JWT payload
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
		"""
		payload = self.validate_token(token)
		user_info = self.extract_user_info(payload)
		return payload, user_info


# Global validator instance
jwt_validator = KeycloakJWTValidator()
