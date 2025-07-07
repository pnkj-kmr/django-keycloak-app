# app/user_keycloak/keycloak/client.py
"""
Keycloak API client for token operations
"""

import json
import time
import logging
import requests
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode
from django.conf import settings

from .exceptions import KeycloakConnectionError, TokenRefreshError, InvalidTokenError
from .redis_util import redis_manager

logger = logging.getLogger('keycloak_auth')


class KeycloakClient:
	"""
	Client for interacting with Keycloak APIs
	"""

	def __init__(self):
		self.keycloak_config = getattr(settings, 'KEYCLOAK_CONFIG', {})
		self.token_url = self.keycloak_config.get('TOKEN_URL')
		self.userinfo_url = self.keycloak_config.get('USERINFO_URL')
		self.introspect_url = self.keycloak_config.get('INTROSPECT_URL')
		self.client_id = self.keycloak_config.get('CLIENT_ID')
		self.client_secret = self.keycloak_config.get('CLIENT_SECRET')

		# Request configuration
		self.timeout = 10
		self.headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}

	def exchange_code_for_tokens(self, authorization_code: str, redirect_uri: str) -> Dict[str, Any]:
		"""
		Exchange authorization code for access and refresh tokens

		Args:
		    authorization_code: Authorization code from OAuth callback
		    redirect_uri: Redirect URI used in initial auth request

		Returns:
		    Dictionary containing tokens and metadata

		Raises:
		    KeycloakConnectionError: If request to Keycloak fails
		    InvalidTokenError: If token exchange fails
		"""
		try:
			# Prepare token exchange request
			data = {
				'grant_type': 'authorization_code',
				'client_id': self.client_id,
				'client_secret': self.client_secret,
				'code': authorization_code,
				'redirect_uri': redirect_uri,
			}

			logger.debug(f'Exchanging code for tokens at {self.token_url}')

			# Make token request
			response = requests.post(self.token_url, data=data, headers=self.headers, timeout=self.timeout)

			if response.status_code == 200:
				token_data = response.json()

				# Add timestamp information
				current_time = int(time.time())
				token_data['issued_at'] = current_time
				token_data['expires_at'] = current_time + token_data.get('expires_in', 3600)

				logger.info('Successfully exchanged authorization code for tokens')
				return token_data

			else:
				error_data = {}
				try:
					error_data = response.json()
				except:
					pass

				logger.error(f'Token exchange failed: {response.status_code} - {error_data}')
				raise InvalidTokenError(
					f'Token exchange failed: {error_data.get("error_description", "Unknown error")}'
				)

		except requests.RequestException as e:
			logger.error(f'Network error during token exchange: {str(e)}')
			raise KeycloakConnectionError(f'Cannot connect to Keycloak: {str(e)}')
		except Exception as e:
			logger.error(f'Unexpected error during token exchange: {str(e)}')
			raise InvalidTokenError(f'Token exchange error: {str(e)}')

	def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
		"""
		Refresh access token using refresh token

		Args:
		    refresh_token: Refresh token

		Returns:
		    Dictionary containing new tokens

		Raises:
		    TokenRefreshError: If token refresh fails
		    KeycloakConnectionError: If request to Keycloak fails
		"""
		try:
			# Prepare refresh request
			data = {
				'grant_type': 'refresh_token',
				'client_id': self.client_id,
				'client_secret': self.client_secret,
				'refresh_token': refresh_token,
			}

			logger.debug('Refreshing access token')

			# Make refresh request
			response = requests.post(self.token_url, data=data, headers=self.headers, timeout=self.timeout)

			if response.status_code == 200:
				token_data = response.json()

				# Add timestamp information
				current_time = int(time.time())
				token_data['issued_at'] = current_time
				token_data['expires_at'] = current_time + token_data.get('expires_in', 3600)

				logger.info('Successfully refreshed access token')
				return token_data

			else:
				error_data = {}
				try:
					error_data = response.json()
				except:
					pass

				logger.error(f'Token refresh failed: {response.status_code} - {error_data}')
				raise TokenRefreshError(f'Token refresh failed: {error_data.get("error_description", "Unknown error")}')

		except requests.RequestException as e:
			logger.error(f'Network error during token refresh: {str(e)}')
			raise KeycloakConnectionError(f'Cannot connect to Keycloak: {str(e)}')
		except Exception as e:
			logger.error(f'Unexpected error during token refresh: {str(e)}')
			raise TokenRefreshError(f'Token refresh error: {str(e)}')

	def get_user_info(self, access_token: str) -> Dict[str, Any]:
		"""
		Get user information from Keycloak userinfo endpoint

		Args:
		    access_token: Valid access token

		Returns:
		    User information dictionary

		Raises:
		    KeycloakConnectionError: If request fails
		    InvalidTokenError: If token is invalid
		"""
		try:
			headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}

			logger.debug('Fetching user info from Keycloak')

			response = requests.get(self.userinfo_url, headers=headers, timeout=self.timeout)

			if response.status_code == 200:
				user_info = response.json()
				logger.debug(f'Successfully fetched user info for: {user_info.get("sub")}')
				return user_info

			elif response.status_code == 401:
				logger.warning('Access token is invalid or expired')
				raise InvalidTokenError('Access token is invalid or expired')

			else:
				logger.error(f'UserInfo request failed: {response.status_code}')
				raise KeycloakConnectionError(f'UserInfo request failed: {response.status_code}')

		except requests.RequestException as e:
			logger.error(f'Network error fetching user info: {str(e)}')
			raise KeycloakConnectionError(f'Cannot fetch user info: {str(e)}')
		except Exception as e:
			logger.error(f'Unexpected error fetching user info: {str(e)}')
			raise KeycloakConnectionError(f'Error fetching user info: {str(e)}')

	def introspect_token(self, token: str) -> Dict[str, Any]:
		"""
		Introspect token to check if it's valid and active

		Args:
		    token: Token to introspect

		Returns:
		    Introspection result dictionary
		"""
		try:
			data = {
				'client_id': self.client_id,
				'client_secret': self.client_secret,
				'token': token,
			}

			logger.debug('Introspecting token')

			response = requests.post(self.introspect_url, data=data, headers=self.headers, timeout=self.timeout)

			if response.status_code == 200:
				introspection_result = response.json()
				logger.debug(f'Token introspection result: active={introspection_result.get("active")}')
				return introspection_result
			else:
				logger.error(f'Token introspection failed: {response.status_code}')
				return {'active': False}

		except Exception as e:
			logger.error(f'Error during token introspection: {str(e)}')
			return {'active': False}

	def logout_user(self, refresh_token: str) -> bool:
		"""
		Logout user by revoking refresh token

		Args:
		    refresh_token: Refresh token to revoke

		Returns:
		    True if logout successful, False otherwise
		"""
		try:
			# Keycloak logout endpoint (if available)
			logout_url = self.keycloak_config.get('LOGOUT_URL')
			if not logout_url:
				logger.warning('No logout URL configured')
				return True  # Assume success if no logout endpoint

			data = {
				'client_id': self.client_id,
				'client_secret': self.client_secret,
				'refresh_token': refresh_token,
			}

			logger.debug('Logging out user via Keycloak')

			response = requests.post(logout_url, data=data, headers=self.headers, timeout=self.timeout)

			success = response.status_code in [200, 204]
			if success:
				logger.info('Successfully logged out user')
			else:
				logger.warning(f'Logout request returned: {response.status_code}')

			return success

		except Exception as e:
			logger.error(f'Error during logout: {str(e)}')
			return False


# Global client instance
keycloak_client = KeycloakClient()
