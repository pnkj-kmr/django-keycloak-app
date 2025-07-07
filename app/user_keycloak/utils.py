"""
Enhanced utility functions for Keycloak integration with Redis
"""

import logging
import secrets
import string
from typing import Dict, Any, Optional
from django.conf import settings
from urllib.parse import urlencode, urlparse

from app.user_keycloak.redis_util import redis_manager


logger = logging.getLogger(__name__)


def get_keycloak_config() -> Dict[str, Any]:
	"""
	Get Keycloak configuration from Django settings

	Returns:
	    Dict containing Keycloak configuration
	"""
	return getattr(settings, 'KEYCLOAK_CONFIG', {})


def generate_state_token(length: int = 32) -> str:
	"""
	Generate a random state token for OAuth2 flow

	Args:
	    length: Length of the generated token

	Returns:
	    Random state token string
	"""
	alphabet = string.ascii_letters + string.digits + '-_'
	return ''.join(secrets.choice(alphabet) for _ in range(length))


def build_keycloak_url(endpoint: str, params: Optional[Dict[str, str]] = None) -> str:
	"""
	Build a complete Keycloak URL with parameters

	Args:
	    endpoint: The Keycloak endpoint URL
	    params: Optional query parameters

	Returns:
	    Complete URL with parameters
	"""
	if params:
		return f'{endpoint}?{urlencode(params)}'
	return endpoint


def log_auth_event(
	event_type: str,
	user_id: Optional[str] = None,
	details: Optional[Dict[str, Any]] = None,
	session_key: Optional[str] = None,
) -> None:
	"""
	Log authentication events for debugging and monitoring

	Args:
	    event_type: Type of authentication event
	    user_id: User identifier (if available)
	    details: Additional event details
	    session_key: Session key for tracking
	"""
	log_data = {'event': event_type, 'user_id': user_id, 'session_key': session_key, 'details': details or {}}
	logger.info(f'Auth Event: {log_data}')


def is_url_safe(url: str, allowed_hosts: Optional[list] = None) -> bool:
	"""
	Check if a URL is safe for redirects

	Args:
	    url: URL to check
	    allowed_hosts: List of allowed hosts

	Returns:
	    True if URL is safe, False otherwise
	"""
	if not url:
		return False

	try:
		parsed = urlparse(url)
		if not parsed.netloc:  # Relative URL
			return True

		if allowed_hosts:
			return parsed.netloc in allowed_hosts

		# Default: only allow same host
		return False
	except Exception:
		return False


def extract_user_roles(token_payload: Dict[str, Any]) -> list:
	"""
	Extract user roles from JWT token payload

	Args:
	    token_payload: Decoded JWT token payload

	Returns:
	    List of user roles
	"""
	roles = []

	# Realm roles
	realm_access = token_payload.get('realm_access', {})
	if isinstance(realm_access, dict):
		roles.extend(realm_access.get('roles', []))

	# Client roles
	resource_access = token_payload.get('resource_access', {})
	client_id = get_keycloak_config().get('CLIENT_ID', '')
	if client_id in resource_access:
		client_roles = resource_access[client_id].get('roles', [])
		roles.extend(client_roles)

	return list(set(roles))  # Remove duplicates


def cache_user_session_data(user_id: str, session_data: Dict[str, Any], expiry: int = 3600) -> bool:
	"""
	Cache user session data in Redis

	Args:
	    user_id: User identifier
	    session_data: Session data to cache
	    expiry: Cache expiry in seconds

	Returns:
	    True if cached successfully
	"""
	try:
		return redis_manager.cache_user_info(user_id, session_data, expiry)
	except Exception as e:
		logger.error(f'Failed to cache user session data: {str(e)}')
		return False


def get_cached_user_session_data(user_id: str) -> Dict[str, Any]:
	"""
	Get cached user session data from Redis

	Args:
	    user_id: User identifier

	Returns:
	    Cached session data or empty dict
	"""
	try:
		return redis_manager.get_cached_user_info(user_id)
	except Exception as e:
		logger.error(f'Failed to get cached user session data: {str(e)}')
		return {}


def store_user_tokens_with_metadata(
	user_id: str, tokens: Dict[str, Any], user_info: Dict[str, Any], expiry: int = 3600
) -> bool:
	"""
	Store both tokens and user metadata in Redis

	Args:
	    user_id: User identifier
	    tokens: Token data
	    user_info: User information
	    expiry: Cache expiry in seconds

	Returns:
	    True if stored successfully
	"""
	try:
		# Store tokens
		tokens_stored = redis_manager.store_user_tokens(user_id, tokens, expiry)

		# Store user info
		info_stored = redis_manager.cache_user_info(user_id, user_info, expiry)

		return tokens_stored and info_stored
	except Exception as e:
		logger.error(f'Failed to store user data: {str(e)}')
		return False


def cleanup_user_session(user_id: str) -> bool:
	"""
	Complete cleanup of user session data from Redis

	Args:
	    user_id: User identifier

	Returns:
	    True if cleaned up successfully
	"""
	try:
		# Remove tokens
		tokens_removed = redis_manager.invalidate_user_tokens(user_id)

		# Remove cached user info
		cache_key = f'user_info:{user_id}'
		from django.core.cache import cache

		cache.delete(cache_key)

		return tokens_removed
	except Exception as e:
		logger.error(f'Failed to cleanup user session: {str(e)}')
		return False


def get_redis_health_status() -> Dict[str, Any]:
	"""
	Get comprehensive Redis health status

	Returns:
	    Dictionary with Redis health information
	"""
	try:
		stats = redis_manager.get_redis_stats()
		cache_stats = redis_manager.get_keycloak_cache_stats()

		return {
			'status': 'healthy' if 'error' not in stats else 'unhealthy',
			'redis_stats': stats,
			'cache_stats': cache_stats,
			'timestamp': int(__import__('time').time()),
		}
	except Exception as e:
		return {'status': 'error', 'error': str(e), 'timestamp': int(__import__('time').time())}
