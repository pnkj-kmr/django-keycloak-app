"""
Redis utilities for Keycloak integration
"""

import redis
import json
import logging
from typing import Dict, Any, Optional, Union
from django.core.cache import cache, caches
from django.conf import settings
from decouple import config

logger = logging.getLogger(__name__)


class KeycloakRedisManager:
	"""
	Manager class for all Redis operations related to Keycloak authentication
	"""

	def __init__(self):
		# Use default cache
		self.cache = cache

		# Try to get sessions cache, fallback to default
		try:
			if 'sessions' in settings.CACHES:
				self.session_cache = caches['sessions']
			else:
				self.session_cache = cache
		except Exception as e:
			logger.warning(f'Sessions cache not available, using default: {e}')
			self.session_cache = cache

	def get_redis_client(self) -> redis.Redis:
		"""
		Get direct Redis client with authentication
		"""
		try:
			# Get Redis configuration
			redis_host = config('REDIS_HOST', default='127.0.0.1')
			redis_port = config('REDIS_PORT', default=6379, cast=int)
			redis_password = config('REDIS_PASSWORD', default=None)
			redis_db = config('REDIS_DB_DEFAULT', default=1, cast=int)
			redis_ssl = config('REDIS_SSL', default=False, cast=bool)

			# Create Redis client with authentication
			client_kwargs = {
				'host': redis_host,
				'port': redis_port,
				'db': redis_db,
				'decode_responses': True,
				'socket_keepalive': True,
				'socket_keepalive_options': {},
				'health_check_interval': 30,
			}

			# Add password if configured
			if redis_password:
				client_kwargs['password'] = redis_password

			# Add SSL if configured
			if redis_ssl:
				client_kwargs['ssl'] = True
				client_kwargs['ssl_cert_reqs'] = None

			redis_client = redis.Redis(**client_kwargs)

			# Test connection
			redis_client.ping()

			return redis_client

		except redis.AuthenticationError as e:
			logger.error(f'Redis authentication failed: {e}')
			raise
		except redis.ConnectionError as e:
			logger.error(f'Redis connection failed: {e}')
			raise
		except Exception as e:
			logger.error(f'Failed to create Redis client: {e}')
			raise

	# Token Management
	def store_user_tokens(self, user_id: str, tokens: Dict[str, Any], expiry: int = 3600) -> bool:
		"""
		Store user tokens in Redis with expiry

		Args:
		    user_id: Unique user identifier
		    tokens: Dictionary containing access_token, refresh_token, etc.
		    expiry: Token expiry time in seconds

		Returns:
		    True if stored successfully, False otherwise
		"""
		cache_key = f'user_tokens:{user_id}'
		try:
			self.cache.set(cache_key, tokens, timeout=expiry)
			logger.debug(f'Stored tokens for user {user_id} with expiry {expiry}s')
			return True
		except Exception as e:
			logger.error(f'Failed to store tokens for user {user_id}: {str(e)}')
			return False

	def get_user_tokens(self, user_id: str) -> Dict[str, Any]:
		"""
		Retrieve user tokens from Redis

		Args:
		    user_id: Unique user identifier

		Returns:
		    Dictionary containing tokens or empty dict if not found
		"""
		cache_key = f'user_tokens:{user_id}'
		try:
			tokens = self.cache.get(cache_key, {})
			if tokens:
				logger.debug(f'Retrieved tokens for user {user_id}')
			return tokens
		except Exception as e:
			logger.error(f'Failed to retrieve tokens for user {user_id}: {str(e)}')
			return {}

	def update_user_tokens(self, user_id: str, new_tokens: Dict[str, Any], expiry: int = 3600) -> bool:
		"""
		Update existing user tokens in Redis

		Args:
		    user_id: Unique user identifier
		    new_tokens: New token data to update
		    expiry: Token expiry time in seconds

		Returns:
		    True if updated successfully, False otherwise
		"""
		existing_tokens = self.get_user_tokens(user_id)
		if existing_tokens:
			existing_tokens.update(new_tokens)
			return self.store_user_tokens(user_id, existing_tokens, expiry)
		else:
			return self.store_user_tokens(user_id, new_tokens, expiry)

	def invalidate_user_tokens(self, user_id: str) -> bool:
		"""
		Remove user tokens from Redis (for logout)

		Args:
		    user_id: Unique user identifier

		Returns:
		    True if invalidated successfully, False otherwise
		"""
		cache_key = f'user_tokens:{user_id}'
		try:
			self.cache.delete(cache_key)
			logger.debug(f'Invalidated tokens for user {user_id}')
			return True
		except Exception as e:
			logger.error(f'Failed to invalidate tokens for user {user_id}: {str(e)}')
			return False

	# JWT Blacklist Management
	def blacklist_jwt(self, jti: str, expiry: int) -> bool:
		"""
		Add JWT ID to blacklist (for token revocation)

		Args:
		    jti: JWT ID from token
		    expiry: When the blacklist entry should expire

		Returns:
		    True if blacklisted successfully, False otherwise
		"""
		cache_key = f'jwt_blacklist:{jti}'
		try:
			self.cache.set(cache_key, True, timeout=expiry)
			logger.debug(f'Blacklisted JWT {jti}')
			return True
		except Exception as e:
			logger.error(f'Failed to blacklist JWT {jti}: {str(e)}')
			return False

	def is_jwt_blacklisted(self, jti: str) -> bool:
		"""
		Check if JWT is blacklisted

		Args:
		    jti: JWT ID to check

		Returns:
		    True if blacklisted, False otherwise
		"""
		cache_key = f'jwt_blacklist:{jti}'
		try:
			return bool(self.cache.get(cache_key, False))
		except Exception as e:
			logger.error(f'Failed to check JWT blacklist for {jti}: {str(e)}')
			return False

	# Keycloak Data Caching
	def cache_keycloak_jwks(self, jwks: Dict[str, Any], expiry: int = 3600) -> bool:
		"""
		Cache Keycloak public keys for JWT validation

		Args:
		    jwks: JWKS (JSON Web Key Set) from Keycloak
		    expiry: Cache expiry time in seconds

		Returns:
		    True if cached successfully, False otherwise
		"""
		cache_key = 'keycloak_jwks'
		try:
			self.cache.set(cache_key, jwks, timeout=expiry)
			logger.debug('Cached Keycloak JWKS')
			return True
		except Exception as e:
			logger.error(f'Failed to cache Keycloak JWKS: {str(e)}')
			return False

	def get_cached_keycloak_jwks(self) -> Dict[str, Any]:
		"""
		Get cached Keycloak public keys

		Returns:
		    JWKS dictionary or empty dict if not cached
		"""
		cache_key = 'keycloak_jwks'
		try:
			jwks = self.cache.get(cache_key, {})
			if jwks:
				logger.debug('Retrieved cached Keycloak JWKS')
			return jwks
		except Exception as e:
			logger.error(f'Failed to get cached Keycloak JWKS: {str(e)}')
			return {}

	def cache_user_info(self, user_id: str, user_info: Dict[str, Any], expiry: int = 300) -> bool:
		"""
		Cache user information from Keycloak

		Args:
		    user_id: Unique user identifier
		    user_info: User information from Keycloak
		    expiry: Cache expiry time in seconds (default: 5 minutes)

		Returns:
		    True if cached successfully, False otherwise
		"""
		cache_key = f'user_info:{user_id}'
		try:
			self.cache.set(cache_key, user_info, timeout=expiry)
			logger.debug(f'Cached user info for {user_id}')
			return True
		except Exception as e:
			logger.error(f'Failed to cache user info for {user_id}: {str(e)}')
			return False

	def get_cached_user_info(self, user_id: str) -> Dict[str, Any]:
		"""
		Get cached user information

		Args:
		    user_id: Unique user identifier

		Returns:
		    User information dictionary or empty dict if not cached
		"""
		cache_key = f'user_info:{user_id}'
		try:
			user_info = self.cache.get(cache_key, {})
			if user_info:
				logger.debug(f'Retrieved cached user info for {user_id}')
			return user_info
		except Exception as e:
			logger.error(f'Failed to get cached user info for {user_id}: {str(e)}')
			return {}

	# Session Management
	def store_oauth_state(self, session_key: str, state: str, expiry: int = 600) -> bool:
		"""
		Store OAuth state parameter for CSRF protection

		Args:
		    session_key: Session identifier
		    state: OAuth state parameter
		    expiry: State expiry time in seconds (default: 10 minutes)

		Returns:
		    True if stored successfully, False otherwise
		"""
		cache_key = f'oauth_state:{session_key}'
		try:
			self.session_cache.set(cache_key, state, timeout=expiry)
			logger.debug(f'Stored OAuth state for session {session_key}')
			return True
		except Exception as e:
			logger.error(f'Failed to store OAuth state: {str(e)}')
			return False

	def verify_oauth_state(self, session_key: str, state: str) -> bool:
		"""
		Verify OAuth state parameter

		Args:
		    session_key: Session identifier
		    state: OAuth state parameter to verify

		Returns:
		    True if state is valid, False otherwise
		"""
		cache_key = f'oauth_state:{session_key}'
		try:
			stored_state = self.session_cache.get(cache_key)
			if stored_state and stored_state == state:
				# Delete state after verification (one-time use)
				self.session_cache.delete(cache_key)
				logger.debug(f'OAuth state verified for session {session_key}')
				return True
			return False
		except Exception as e:
			logger.error(f'Failed to verify OAuth state: {str(e)}')
			return False

	# Statistics and Monitoring
	def get_redis_stats(self) -> Dict[str, Any]:
		"""
		Get Redis connection and usage statistics

		Returns:
		    Dictionary containing Redis statistics
		"""
		try:
			redis_client = self.get_redis_client()
			info = redis_client.info()
			return {
				'connected_clients': info.get('connected_clients', 0),
				'used_memory_human': info.get('used_memory_human', '0B'),
				'used_memory': info.get('used_memory', 0),
				'keyspace_hits': info.get('keyspace_hits', 0),
				'keyspace_misses': info.get('keyspace_misses', 0),
				'total_commands_processed': info.get('total_commands_processed', 0),
				'redis_version': info.get('redis_version', 'unknown'),
				'uptime_in_seconds': info.get('uptime_in_seconds', 0),
				'role': info.get('role', 'unknown'),
			}
		except Exception as e:
			logger.error(f'Failed to get Redis stats: {str(e)}')
			return {'error': str(e)}

	def get_keycloak_cache_stats(self) -> Dict[str, Any]:
		"""
		Get statistics about cached Keycloak data

		Returns:
		    Dictionary containing cache statistics
		"""
		try:
			redis_client = self.get_redis_client()

			# Count different types of cached data
			prefix = settings.CACHES['default'].get('KEY_PREFIX', '')

			patterns = {
				'user_tokens': f'{prefix}:*:user_tokens:*',
				'jwt_blacklist': f'{prefix}:*:jwt_blacklist:*',
				'user_info': f'{prefix}:*:user_info:*',
				'keycloak_jwks': f'{prefix}:*:keycloak_jwks',
				'oauth_states': f'{prefix}:*:oauth_state:*',
			}

			stats = {}
			for key_type, pattern in patterns.items():
				try:
					keys = redis_client.keys(pattern)
					stats[f'{key_type}_count'] = len(keys)
				except Exception:
					stats[f'{key_type}_count'] = 0

			return stats
		except Exception as e:
			logger.error(f'Failed to get Keycloak cache stats: {str(e)}')
			return {'error': str(e)}

	def cleanup_expired_data(self) -> Dict[str, int]:
		"""
		Manual cleanup of expired data (Redis handles this automatically)
		This is mainly for monitoring and statistics

		Returns:
		    Dictionary with cleanup statistics
		"""  # noqa: E101
		try:
			redis_client = self.get_redis_client()

			# This is mainly for getting statistics
			# Redis automatically handles TTL expiration
			info = redis_client.info()

			return {
				'expired_keys': info.get('expired_keys', 0),
				'evicted_keys': info.get('evicted_keys', 0),
			}
		except Exception as e:
			logger.error(f'Failed to get cleanup stats: {str(e)}')
			return {'error': str(e)}


# Global instance
redis_manager = KeycloakRedisManager()
