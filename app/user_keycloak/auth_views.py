# app/user_keycloak/auth_views.py
"""
Complete authentication views with JWT validation - Phase 3
"""

import logging
import json
import time
import requests
from typing import Optional
from urllib.parse import urlencode

from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.urls import reverse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache

from .utils import (
	get_keycloak_config,
	generate_state_token,
	build_keycloak_url,
	log_auth_event,
	is_url_safe,
	get_redis_health_status,
	store_user_tokens_with_metadata,
	cleanup_user_session,
)
from .redis_util import redis_manager
from .client import keycloak_client
from .user import KeycloakUser
from .exceptions import (
	OAuthStateError,
	TokenRefreshError,
	TokenValidationError,
	KeycloakConnectionError,
	RedisConnectionError,
)

logger = logging.getLogger('keycloak_auth')


@never_cache
def keycloak_login(request):
	"""
	Redirect user to Keycloak login page with proper OAuth2 flow
	"""
	try:
		keycloak_config = get_keycloak_config()

		# Get redirect URI for callback
		redirect_uri = request.build_absolute_uri(reverse('keycloak_auth:callback'))

		# Generate state token for CSRF protection
		state_token = generate_state_token()

		# Store OAuth state in Redis
		session_key = request.session.session_key
		if not session_key:
			request.session.create()
			session_key = request.session.session_key

		redis_manager.store_oauth_state(session_key, state_token, expiry=600)  # 10 minutes

		# Store original requested URL for post-login redirect
		next_url = request.GET.get('next', '/')
		if is_url_safe(next_url):
			request.session['post_login_redirect'] = next_url

		# Build OAuth2 authorization parameters
		auth_params = {
			'client_id': keycloak_config['CLIENT_ID'],
			'response_type': keycloak_config['RESPONSE_TYPE'],
			'redirect_uri': redirect_uri,
			'scope': keycloak_config['SCOPE'],
			'state': state_token,
		}

		# Build complete authorization URL
		auth_url = build_keycloak_url(keycloak_config['AUTHORIZATION_URL'], auth_params)

		log_auth_event('login_redirect', session_key=session_key, details={'redirect_uri': redirect_uri})
		logger.info(f'Redirecting to Keycloak login: {auth_url}')

		return redirect(auth_url)

	except RedisConnectionError as e:
		logger.error(f'Redis connection failed during login: {str(e)}')
		return render(
			request, 'auth/error.html', {'error': 'Authentication service temporarily unavailable. Please try again.'}
		)
	except Exception as e:
		logger.error(f'Login redirect failed: {str(e)}')
		return render(request, 'auth/error.html', {'error': 'Login failed. Please try again.'})


@csrf_exempt
@require_http_methods(['GET'])
@never_cache
def keycloak_callback(request):
	"""
	Handle OAuth2 callback from Keycloak with complete token exchange
	"""
	try:
		# Check for errors from Keycloak
		error = request.GET.get('error')
		if error:
			error_description = request.GET.get('error_description', 'Unknown error')
			log_auth_event('callback_error', details={'error': error, 'description': error_description})
			logger.error(f'Keycloak authentication error: {error} - {error_description}')

			return render(request, 'auth/error.html', {'error': f'Authentication failed: {error_description}'})

		# Get authorization code
		code = request.GET.get('code')
		if not code:
			log_auth_event('callback_error', details={'error': 'no_code'})
			logger.error('No authorization code received from Keycloak')
			return HttpResponseBadRequest('No authorization code received from Keycloak')

		# Verify state parameter using Redis
		received_state = request.GET.get('state')
		session_key = request.session.session_key

		if not session_key or not redis_manager.verify_oauth_state(session_key, received_state):
			log_auth_event('callback_error', details={'error': 'invalid_state'})
			logger.error('Invalid or missing state parameter')
			raise OAuthStateError('Invalid state parameter')

		try:
			# Exchange authorization code for tokens
			redirect_uri = request.build_absolute_uri(reverse('keycloak_auth:callback'))
			token_data = keycloak_client.exchange_code_for_tokens(code, redirect_uri)

			# Validate access token and extract user info
			access_token = token_data['access_token']
			user = KeycloakUser.from_access_token(access_token)

			# Add refresh token to user tokens if available
			if 'refresh_token' in token_data:
				user.tokens['refresh_token'] = token_data['refresh_token']

			# Store comprehensive token data
			complete_tokens = {
				'access_token': token_data['access_token'],
				'refresh_token': token_data.get('refresh_token'),
				'id_token': token_data.get('id_token'),
				'token_type': token_data.get('token_type', 'Bearer'),
				'expires_in': token_data.get('expires_in', 3600),
				'expires_at': token_data.get('expires_at'),
				'issued_at': token_data.get('issued_at'),
				'scope': token_data.get('scope', 'openid profile email'),
			}

			# Store tokens and user info in Redis
			success = store_user_tokens_with_metadata(
				user.id, complete_tokens, user.user_info, expiry=token_data.get('expires_in', 3600)
			)

			if not success:
				raise RedisConnectionError('Failed to store user data')

			# Store session data
			request.session['user_id'] = user.id
			request.session['authenticated'] = True
			request.session['login_time'] = int(time.time())

			log_auth_event(
				'callback_success', user_id=user.id, details={'username': user.username, 'roles': user.roles}
			)
			logger.info(f'Successfully authenticated user {user.username} ({user.id})')

			# Redirect to original requested URL or default
			next_url = request.session.pop('post_login_redirect', '/')
			return redirect(next_url)

		except TokenValidationError as e:
			log_auth_event('callback_error', details={'error': 'token_validation_failed'})
			logger.error(f'Token validation failed: {str(e)}')
			return render(
				request, 'auth/error.html', {'error': 'Authentication token validation failed. Please try again.'}
			)

		except KeycloakConnectionError as e:
			log_auth_event('callback_error', details={'error': 'keycloak_connection_failed'})
			logger.error(f'Keycloak connection failed: {str(e)}')
			return render(
				request, 'auth/error.html', {'error': 'Unable to connect to authentication service. Please try again.'}
			)

		except RedisConnectionError as e:
			log_auth_event('callback_error', details={'error': 'redis_failure'})
			logger.error(f'Redis operation failed during callback: {str(e)}')
			return render(request, 'auth/error.html', {'error': 'Authentication service temporarily unavailable.'})

	except OAuthStateError as e:
		return render(request, 'auth/error.html', {'error': 'Invalid authentication request. Please try again.'})
	except Exception as e:
		log_auth_event('callback_error', details={'error': str(e)})
		logger.error(f'Callback processing failed: {str(e)}')
		return render(request, 'auth/error.html', {'error': 'Authentication failed. Please try again.'})


@never_cache
def keycloak_logout(request):
	"""
	Enhanced logout with Keycloak session termination and Redis cleanup
	"""
	try:
		keycloak_config = get_keycloak_config()

		# Get user info for cleanup
		user_id = request.session.get('user_id')

		if user_id:
			# Get tokens for Keycloak logout
			user_tokens = redis_manager.get_user_tokens(user_id)
			refresh_token = user_tokens.get('refresh_token')
			id_token = user_tokens.get('id_token')

			# Logout from Keycloak (revoke refresh token)
			if refresh_token:
				try:
					keycloak_client.logout_user(refresh_token)
				except Exception as e:
					logger.warning(f'Keycloak logout failed: {str(e)}')

			# Cleanup all user data from Redis
			cleanup_success = cleanup_user_session(user_id)
			if not cleanup_success:
				logger.warning(f'Failed to cleanup Redis data for user {user_id}')

			log_auth_event('logout', user_id=user_id)

		# Clear Django session
		request.session.flush()

		# Build Keycloak logout URL for frontend logout
		redirect_uri = request.build_absolute_uri('/')
		logout_params = {
			'redirect_uri': redirect_uri,
			'client_id': keycloak_config['CLIENT_ID'],
		}

		# Add id_token_hint if available (recommended by OIDC spec)
		if user_id and id_token:
			logout_params['id_token_hint'] = id_token

		logout_url = build_keycloak_url(keycloak_config['LOGOUT_URL'], logout_params)

		logger.info(f'Logging out user {user_id}, redirecting to: {logout_url}')
		return redirect(logout_url)

	except Exception as e:
		logger.error(f'Logout failed: {str(e)}')
		# Even if logout fails, clear session and redirect to home
		request.session.flush()
		return redirect('/')


@csrf_exempt
@require_http_methods(['POST'])
def refresh_token(request):
	"""
	Refresh access token using refresh token with full Keycloak integration
	"""
	try:
		# Parse request body
		data = json.loads(request.body)
		refresh_token = data.get('refresh_token')
		user_id = data.get('user_id') or request.session.get('user_id')

		if not refresh_token or not user_id:
			return JsonResponse({'error': 'Missing refresh token or user ID'}, status=400)

		# Get stored tokens from Redis for validation
		stored_tokens = redis_manager.get_user_tokens(user_id)
		if not stored_tokens or stored_tokens.get('refresh_token') != refresh_token:
			return JsonResponse({'error': 'Invalid refresh token'}, status=401)

		try:
			# Refresh tokens with Keycloak
			new_token_data = keycloak_client.refresh_access_token(refresh_token)

			# Validate new access token
			new_user = KeycloakUser.from_access_token(new_token_data['access_token'])

			# Update complete token data
			updated_tokens = {
				'access_token': new_token_data['access_token'],
				'refresh_token': new_token_data.get('refresh_token', refresh_token),
				'id_token': new_token_data.get('id_token'),
				'token_type': new_token_data.get('token_type', 'Bearer'),
				'expires_in': new_token_data.get('expires_in', 3600),
				'expires_at': new_token_data.get('expires_at'),
				'issued_at': new_token_data.get('issued_at'),
				'scope': new_token_data.get('scope', stored_tokens.get('scope')),
			}

			# Update Redis with new tokens and user info
			update_success = redis_manager.update_user_tokens(
				user_id, updated_tokens, new_token_data.get('expires_in', 3600)
			)

			# Also update user info in case it changed
			redis_manager.cache_user_info(user_id, new_user.user_info, 3600)

			if not update_success:
				raise RedisConnectionError('Failed to update tokens')

			log_auth_event('token_refreshed', user_id=user_id)
			logger.info(f'Token refreshed successfully for user {user_id}')

			return JsonResponse(
				{
					'access_token': updated_tokens['access_token'],
					'token_type': updated_tokens['token_type'],
					'expires_in': updated_tokens['expires_in'],
					'expires_at': updated_tokens['expires_at'],
					'scope': updated_tokens['scope'],
				}
			)

		except TokenRefreshError as e:
			logger.error(f'Token refresh failed for user {user_id}: {str(e)}')
			# Clean up invalid tokens
			redis_manager.invalidate_user_tokens(user_id)
			return JsonResponse({'error': 'Token refresh failed', 'details': str(e)}, status=401)

		except TokenValidationError as e:
			logger.error(f'New token validation failed for user {user_id}: {str(e)}')
			return JsonResponse({'error': 'New token validation failed'}, status=401)

		except RedisConnectionError as e:
			logger.error(f'Redis operation failed during token refresh: {str(e)}')
			return JsonResponse({'error': 'Token refresh service temporarily unavailable'}, status=503)

	except json.JSONDecodeError:
		return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
	except Exception as e:
		logger.error(f'Token refresh error: {str(e)}')
		return JsonResponse({'error': 'Token refresh failed'}, status=500)


@require_http_methods(['GET'])
def user_info(request):
	"""
	Get current authenticated user information with real JWT data
	"""
	try:
		# Check if user is authenticated
		user_id = request.session.get('user_id')
		if not user_id or not request.session.get('authenticated'):
			return JsonResponse({'error': 'Not authenticated'}, status=401)

		# Get user data from Redis
		user_tokens = redis_manager.get_user_tokens(user_id)
		user_info = redis_manager.get_cached_user_info(user_id)

		if not user_tokens or not user_info:
			# Try to get fresh data from access token
			access_token = user_tokens.get('access_token') if user_tokens else None
			if access_token:
				try:
					user = KeycloakUser.from_access_token(access_token)
					user_data = user.to_dict()
				except TokenValidationError:
					# Token is invalid, user needs to re-authenticate
					request.session.flush()
					return JsonResponse({'error': 'Token expired, please login again'}, status=401)
			else:
				return JsonResponse({'error': 'User information not available'}, status=404)
		else:
			# Create user object from cached data
			user = KeycloakUser(user_id, user_tokens, user_info)
			user_data = user.to_dict()

		log_auth_event('user_info_requested', user_id=user_id)

		return JsonResponse(
			{
				'user': user_data,
				'session_info': {
					'login_time': request.session.get('login_time'),
					'session_key': request.session.session_key,
				},
			}
		)

	except Exception as e:
		logger.error(f'Failed to get user info: {str(e)}')
		return JsonResponse({'error': 'Failed to retrieve user information'}, status=500)


@require_http_methods(['GET'])
def auth_status(request):
	"""
	Check authentication status with comprehensive information
	"""
	try:
		user_id = request.session.get('user_id')
		is_authenticated = bool(user_id and request.session.get('authenticated', False))

		response_data = {
			'authenticated': is_authenticated,
			'login_url': '/auth/login/',
			'logout_url': '/auth/logout/',
			'timestamp': int(time.time()),
		}

		if is_authenticated and user_id:
			# Get additional info from Redis
			user_tokens = redis_manager.get_user_tokens(user_id)
			user_info = redis_manager.get_cached_user_info(user_id)

			if user_tokens and user_info:
				user = KeycloakUser(user_id, user_tokens, user_info)

				response_data.update(
					{
						'user_id': user_id,
						'username': user.username,
						'email': user.email,
						'roles': user.roles,
						'groups': user.groups,
						'login_time': request.session.get('login_time'),
						'token_expires_at': user.get_token_expiry_time(),
						'token_remaining_seconds': user.get_token_remaining_time(),
						'token_expired': user.is_token_expired(),
					}
				)
			else:
				# User session exists but no Redis data
				response_data.update({'warning': 'Session exists but user data not found in cache'})

		return JsonResponse(response_data)

	except Exception as e:
		logger.error(f'Failed to get auth status: {str(e)}')
		return JsonResponse({'authenticated': False, 'error': 'Failed to check authentication status'})


@require_http_methods(['GET'])
def redis_health(request):
	"""
	Check Redis connection health and cache statistics
	"""
	try:
		health_status = get_redis_health_status()

		# Add additional health checks
		health_status['cache_test'] = _test_redis_operations()
		health_status['keycloak_config'] = _test_keycloak_config()

		status_code = 200 if health_status['status'] == 'healthy' else 503
		return JsonResponse(health_status, status=status_code)

	except Exception as e:
		return JsonResponse({'status': 'error', 'error': str(e), 'timestamp': int(time.time())}, status=500)


@require_http_methods(['POST'])
@csrf_exempt
def invalidate_user_session(request):
	"""
	Manually invalidate a user session (admin endpoint)
	"""
	try:
		data = json.loads(request.body)
		target_user_id = data.get('user_id')

		if not target_user_id:
			return JsonResponse({'error': 'User ID required'}, status=400)

		# Check if current user has admin privileges
		current_user_id = request.session.get('user_id')
		if current_user_id:
			user_info = redis_manager.get_cached_user_info(current_user_id)
			if user_info and 'admin' not in user_info.get('roles', []):
				return JsonResponse({'error': 'Admin privileges required'}, status=403)
		else:
			return JsonResponse({'error': 'Authentication required'}, status=401)

		# Cleanup user session
		cleanup_success = cleanup_user_session(target_user_id)

		if cleanup_success:
			log_auth_event('session_invalidated', user_id=current_user_id, details={'target_user': target_user_id})
			return JsonResponse({'status': 'success', 'message': f'Session invalidated for user {target_user_id}'})
		else:
			return JsonResponse({'error': 'Failed to invalidate session'}, status=500)

	except json.JSONDecodeError:
		return JsonResponse({'error': 'Invalid JSON'}, status=400)
	except Exception as e:
		logger.error(f'Session invalidation failed: {str(e)}')
		return JsonResponse({'error': 'Session invalidation failed'}, status=500)


@require_http_methods(['GET'])
def test_user_backend(request):
	"""
	Test the authentication backend and user creation
	"""
	try:
		if hasattr(request, 'user') and request.user:
			user_data = {
				'authenticated': True,
				'user_id': request.user.id,
				'username': request.user.username,
				'email': request.user.email,
				'full_name': request.user.get_full_name(),
				'roles': request.user.roles,
				'groups': request.user.groups,
				'is_staff': request.user.is_staff,
				'is_superuser': request.user.is_superuser,
				'token_expired': request.user.is_token_expired(),
				'token_remaining_seconds': request.user.get_token_remaining_time(),
				'permissions': list(request.user.get_all_permissions()),
			}

			return JsonResponse({'status': 'success', 'user': user_data})
		else:
			return JsonResponse({'status': 'unauthenticated', 'message': 'No user found'}, status=401)

	except Exception as e:
		return JsonResponse({'status': 'error', 'error': str(e)}, status=500)


def _test_redis_operations() -> dict:
	"""Test basic Redis operations for health check"""
	try:
		test_key = f'health_test_{int(time.time())}'
		test_value = 'test_value'

		# Test set/get
		set_success = redis_manager.cache.set(test_key, test_value, timeout=60)
		get_success = redis_manager.cache.get(test_key) == test_value

		# Test token operations
		token_test_user = f'test_user_{int(time.time())}'
		token_store_success = redis_manager.store_user_tokens(token_test_user, {'access_token': 'test_token'}, 60)
		token_get_success = bool(redis_manager.get_user_tokens(token_test_user))

		# Cleanup
		redis_manager.cache.delete(test_key)
		redis_manager.invalidate_user_tokens(token_test_user)

		return {
			'basic_operations': set_success and get_success,
			'token_operations': token_store_success and token_get_success,
			'overall': set_success and get_success and token_store_success and token_get_success,
		}
	except Exception as e:
		logger.error(f'Redis health test failed: {str(e)}')
		return {'basic_operations': False, 'token_operations': False, 'overall': False, 'error': str(e)}


def _test_keycloak_config() -> dict:
	"""Test Keycloak configuration"""
	try:
		keycloak_config = get_keycloak_config()

		required_keys = [
			'SERVER_URL',
			'REALM',
			'CLIENT_ID',
			'CLIENT_SECRET',
			'AUTHORIZATION_URL',
			'TOKEN_URL',
			'JWKS_URL',
		]

		missing_keys = [key for key in required_keys if not keycloak_config.get(key)]

		# Test JWKS endpoint connectivity
		jwks_reachable = False
		try:
			response = requests.get(keycloak_config.get('JWKS_URL'), timeout=5)
			jwks_reachable = response.status_code == 200
		except:
			pass

		return {
			'config_complete': len(missing_keys) == 0,
			'missing_keys': missing_keys,
			'jwks_reachable': jwks_reachable,
			'overall': len(missing_keys) == 0 and jwks_reachable,
		}
	except Exception as e:
		return {'config_complete': False, 'error': str(e), 'overall': False}
