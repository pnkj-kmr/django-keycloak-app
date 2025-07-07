# """
# Enhanced authentication views for Keycloak integration with Redis
# """

# import logging
# import json
# from typing import Optional, Dict
# from urllib.parse import urlencode

# from django.shortcuts import redirect, render
# from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
# from django.urls import reverse
# from django.conf import settings
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_http_methods
# from django.views.decorators.cache import never_cache

# from .utils import (
# 	get_keycloak_config,
# 	generate_state_token,
# 	build_keycloak_url,
# 	log_auth_event,
# 	is_url_safe,
# 	get_redis_health_status,
# 	store_user_tokens_with_metadata,
# 	cleanup_user_session,
# )
# from .redis_util import redis_manager
# from .exceptions import OAuthStateError, TokenRefreshError, RedisConnectionError

# logger = logging.getLogger(__name__)


# @never_cache
# def keycloak_login(request):
# 	"""
# 	Redirect user to Keycloak login page with Redis state management
# 	"""
# 	try:
# 		keycloak_config = get_keycloak_config()

# 		# Get redirect URI for callback
# 		redirect_uri = request.build_absolute_uri(reverse('keycloak_auth:callback'))

# 		# Generate state token for CSRF protection
# 		state_token = generate_state_token()

# 		# Store state in Redis instead of session
# 		session_key = request.session.session_key
# 		if not session_key:
# 			request.session.create()
# 			session_key = request.session.session_key

# 		# Store OAuth state in Redis
# 		redis_manager.store_oauth_state(session_key, state_token, expiry=600)  # 10 minutes

# 		# Store original requested URL for post-login redirect
# 		next_url = request.GET.get('next', '/')
# 		if is_url_safe(next_url):
# 			request.session['post_login_redirect'] = next_url

# 		# Build OAuth2 authorization parameters
# 		auth_params = {
# 			'client_id': keycloak_config['CLIENT_ID'],
# 			'response_type': keycloak_config['RESPONSE_TYPE'],
# 			'redirect_uri': redirect_uri,
# 			'scope': keycloak_config['SCOPE'],
# 			'state': state_token,
# 		}

# 		# Build complete authorization URL
# 		auth_url = build_keycloak_url(keycloak_config['AUTHORIZATION_URL'], auth_params)

# 		log_auth_event('login_redirect', session_key=session_key, details={'redirect_uri': redirect_uri})
# 		logger.info(f'Redirecting to Keycloak login: {auth_url}')

# 		return redirect(auth_url)

# 	except RedisConnectionError as e:
# 		logger.error(f'Redis connection failed during login: {str(e)}')
# 		return render(
# 			request, 'auth/error.html', {'error': 'Authentication service temporarily unavailable. Please try again.'}
# 		)
# 	except Exception as e:
# 		logger.error(f'Login redirect failed: {str(e)}')
# 		return render(request, 'auth/error.html', {'error': 'Login failed. Please try again.'})


# @csrf_exempt
# @require_http_methods(['GET'])
# @never_cache
# def keycloak_callback(request):
# 	"""
# 	Handle OAuth2 callback from Keycloak with Redis token storage
# 	"""
# 	try:
# 		# Check for errors from Keycloak
# 		error = request.GET.get('error')
# 		if error:
# 			error_description = request.GET.get('error_description', 'Unknown error')
# 			log_auth_event('callback_error', details={'error': error, 'description': error_description})
# 			logger.error(f'Keycloak authentication error: {error} - {error_description}')

# 			return render(request, 'auth/error.html', {'error': f'Authentication failed: {error_description}'})

# 		# Get authorization code
# 		code = request.GET.get('code')
# 		if not code:
# 			log_auth_event('callback_error', details={'error': 'no_code'})
# 			logger.error('No authorization code received from Keycloak')
# 			return HttpResponseBadRequest('No authorization code received from Keycloak')

# 		# Verify state parameter using Redis
# 		received_state = request.GET.get('state')
# 		session_key = request.session.session_key

# 		if not session_key or not redis_manager.verify_oauth_state(session_key, received_state):
# 			log_auth_event('callback_error', details={'error': 'invalid_state'})
# 			logger.error('Invalid or missing state parameter')
# 			raise OAuthStateError('Invalid state parameter')

# 		try:
# 			# TODO: In Phase 3, we'll implement:
# 			# 1. Exchange authorization code for tokens
# 			# 2. Validate access token
# 			# 3. Extract user info from token
# 			# 4. Store tokens and user data in Redis

# 			# For Phase 2, create placeholder data
# 			user_id = f'user_{code[:8]}'

# 			# Placeholder tokens
# 			tokens = {
# 				'access_token': f'placeholder_access_token_{code[:10]}',
# 				'refresh_token': f'placeholder_refresh_token_{code[:10]}',
# 				'id_token': f'placeholder_id_token_{code[:10]}',
# 				'token_type': 'Bearer',
# 				'expires_in': 3600,
# 				'expires_at': int(__import__('time').time()) + 3600,
# 				'scope': 'openid profile email',
# 			}

# 			# Placeholder user info
# 			user_info = {
# 				'sub': user_id,
# 				'preferred_username': f'testuser_{code[:4]}',
# 				'email': f'testuser_{code[:4]}@example.com',
# 				'given_name': 'Test',
# 				'family_name': 'User',
# 				'roles': ['user'],
# 				'groups': [],
# 			}

# 			# Store tokens and user info in Redis
# 			success = store_user_tokens_with_metadata(user_id, tokens, user_info, expiry=3600)

# 			if not success:
# 				raise RedisConnectionError('Failed to store user data')

# 			# Store minimal session data
# 			request.session['user_id'] = user_id
# 			request.session['authenticated'] = True
# 			request.session['login_time'] = int(__import__('time').time())

# 			log_auth_event('callback_success', user_id=user_id, details={'code_length': len(code)})
# 			logger.info(f'Successfully authenticated user {user_id}')

# 			# Redirect to original requested URL or default
# 			next_url = request.session.pop('post_login_redirect', '/')
# 			return redirect(next_url)

# 		except RedisConnectionError as e:
# 			log_auth_event('callback_error', details={'error': 'redis_failure'})
# 			logger.error(f'Redis operation failed during callback: {str(e)}')
# 			return render(request, 'auth/error.html', {'error': 'Authentication service temporarily unavailable.'})

# 	except OAuthStateError as e:
# 		return render(request, 'auth/error.html', {'error': 'Invalid authentication request. Please try again.'})
# 	except Exception as e:
# 		log_auth_event('callback_error', details={'error': str(e)})
# 		logger.error(f'Callback processing failed: {str(e)}')
# 		return render(request, 'auth/error.html', {'error': 'Authentication failed. Please try again.'})


# @never_cache
# def keycloak_logout(request):
# 	"""
# 	Enhanced logout with Redis cleanup
# 	"""
# 	try:
# 		keycloak_config = get_keycloak_config()

# 		# Get user info for cleanup
# 		user_id = request.session.get('user_id')

# 		if user_id:
# 			# Get tokens before cleanup for Keycloak logout
# 			user_tokens = redis_manager.get_user_tokens(user_id)
# 			id_token = user_tokens.get('id_token')

# 			# Cleanup all user data from Redis
# 			cleanup_success = cleanup_user_session(user_id)
# 			if not cleanup_success:
# 				logger.warning(f'Failed to cleanup Redis data for user {user_id}')

# 			log_auth_event('logout', user_id=user_id)

# 		# Clear Django session
# 		request.session.flush()

# 		# Build Keycloak logout URL
# 		redirect_uri = request.build_absolute_uri('/')
# 		logout_params = {
# 			'redirect_uri': redirect_uri,
# 			'client_id': keycloak_config['CLIENT_ID'],
# 		}

# 		# Add id_token_hint if available (recommended by OIDC spec)
# 		if user_id and 'id_token' in locals():
# 			logout_params['id_token_hint'] = id_token

# 		logout_url = build_keycloak_url(keycloak_config['LOGOUT_URL'], logout_params)

# 		logger.info(f'Logging out user {user_id}, redirecting to: {logout_url}')
# 		return redirect(logout_url)

# 	except Exception as e:
# 		logger.error(f'Logout failed: {str(e)}')
# 		# Even if logout fails, clear session and redirect to home
# 		request.session.flush()
# 		return redirect('/')


# @csrf_exempt
# @require_http_methods(['POST'])
# def refresh_token(request):
# 	"""
# 	Refresh access token using refresh token with Redis storage
# 	"""
# 	try:
# 		# Parse request body
# 		data = json.loads(request.body)
# 		refresh_token = data.get('refresh_token')
# 		user_id = data.get('user_id') or request.session.get('user_id')

# 		if not refresh_token or not user_id:
# 			return JsonResponse({'error': 'Missing refresh token or user ID'}, status=400)

# 		# Get stored tokens from Redis
# 		stored_tokens = redis_manager.get_user_tokens(user_id)
# 		if not stored_tokens or stored_tokens.get('refresh_token') != refresh_token:
# 			return JsonResponse({'error': 'Invalid refresh token'}, status=401)

# 		try:
# 			# TODO: In Phase 3, implement actual token refresh:
# 			# 1. Make request to Keycloak token endpoint
# 			# 2. Validate refresh token
# 			# 3. Get new access token
# 			# 4. Update Redis with new tokens

# 			# Phase 2 placeholder
# 			new_tokens = {
# 				'access_token': f'new_placeholder_access_token_{int(__import__("time").time())}',
# 				'refresh_token': refresh_token,  # Refresh token usually stays the same
# 				'token_type': 'Bearer',
# 				'expires_in': 3600,
# 				'expires_at': int(__import__('time').time()) + 3600,
# 			}

# 			# Update tokens in Redis
# 			update_success = redis_manager.update_user_tokens(user_id, new_tokens, 3600)
# 			if not update_success:
# 				raise RedisConnectionError('Failed to update tokens')

# 			log_auth_event('token_refreshed', user_id=user_id)
# 			logger.info(f'Token refreshed successfully for user {user_id}')

# 			return JsonResponse(
# 				{
# 					'access_token': new_tokens['access_token'],
# 					'token_type': new_tokens['token_type'],
# 					'expires_in': new_tokens['expires_in'],
# 					'scope': stored_tokens.get('scope', 'openid profile email'),
# 				}
# 			)

# 		except RedisConnectionError as e:
# 			logger.error(f'Redis operation failed during token refresh: {str(e)}')
# 			return JsonResponse({'error': 'Token refresh service temporarily unavailable'}, status=503)

# 	except json.JSONDecodeError:
# 		return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
# 	except Exception as e:
# 		logger.error(f'Token refresh error: {str(e)}')
# 		return JsonResponse({'error': 'Token refresh failed'}, status=500)


# @require_http_methods(['GET'])
# def user_info(request):
# 	"""
# 	Get current authenticated user information from Redis
# 	"""
# 	try:
# 		# Check if user is authenticated
# 		user_id = request.session.get('user_id')
# 		if not user_id or not request.session.get('authenticated'):
# 			return JsonResponse({'error': 'Not authenticated'}, status=401)

# 		# Get user info from Redis cache
# 		user_info = redis_manager.get_cached_user_info(user_id)
# 		if not user_info:
# 			# If not cached, get from stored tokens (Phase 3 will decode from JWT)
# 			return JsonResponse({'error': 'User information not available'}, status=404)

# 		# Get token info
# 		tokens = redis_manager.get_user_tokens(user_id)

# 		log_auth_event('user_info_requested', user_id=user_id)

# 		return JsonResponse(
# 			{
# 				'user': {
# 					'id': user_info.get('sub', user_id),
# 					'username': user_info.get('preferred_username'),
# 					'email': user_info.get('email'),
# 					'first_name': user_info.get('given_name'),
# 					'last_name': user_info.get('family_name'),
# 					'roles': user_info.get('roles', []),
# 					'groups': user_info.get('groups', []),
# 				},
# 				'token_info': {
# 					'expires_at': tokens.get('expires_at'),
# 					'token_type': tokens.get('token_type', 'Bearer'),
# 					'scope': tokens.get('scope', 'openid profile email'),
# 				},
# 			}
# 		)

# 	except Exception as e:
# 		logger.error(f'Failed to get user info: {str(e)}')
# 		return JsonResponse({'error': 'Failed to retrieve user information'}, status=500)


# @require_http_methods(['GET'])
# def auth_status(request):
# 	"""
# 	Check authentication status with Redis data
# 	"""
# 	try:
# 		user_id = request.session.get('user_id')
# 		is_authenticated = bool(user_id and request.session.get('authenticated', False))

# 		response_data = {
# 			'authenticated': is_authenticated,
# 			'login_url': request.build_absolute_uri(reverse('keycloak_auth:login')),
# 			'logout_url': request.build_absolute_uri(reverse('keycloak_auth:logout')),
# 		}

# 		if is_authenticated and user_id:
# 			# Get additional info from Redis
# 			user_info = redis_manager.get_cached_user_info(user_id)
# 			tokens = redis_manager.get_user_tokens(user_id)

# 			response_data.update(
# 				{
# 					'user_id': user_id,
# 					'username': user_info.get('preferred_username', 'unknown'),
# 					'login_time': request.session.get('login_time'),
# 					'token_expires_at': tokens.get('expires_at'),
# 				}
# 			)

# 		return JsonResponse(response_data)

# 	except Exception as e:
# 		logger.error(f'Failed to get auth status: {str(e)}')
# 		return JsonResponse({'authenticated': False, 'error': 'Failed to check authentication status'})


# @require_http_methods(['GET'])
# def redis_health(request):
# 	"""
# 	Check Redis connection health and cache statistics
# 	"""
# 	try:
# 		health_status = get_redis_health_status()

# 		# Add additional health checks
# 		health_status['cache_test'] = _test_redis_operations()

# 		status_code = 200 if health_status['status'] == 'healthy' else 503
# 		return JsonResponse(health_status, status=status_code)

# 	except Exception as e:
# 		return JsonResponse(
# 			{'status': 'error', 'error': str(e), 'timestamp': int(__import__('time').time())}, status=500
# 		)


# @require_http_methods(['POST'])
# @csrf_exempt
# def invalidate_user_session(request):
# 	"""
# 	Manually invalidate a user session (admin endpoint)
# 	"""
# 	try:
# 		data = json.loads(request.body)
# 		target_user_id = data.get('user_id')

# 		if not target_user_id:
# 			return JsonResponse({'error': 'User ID required'}, status=400)

# 		# TODO: Add admin permission check in Phase 3

# 		# Cleanup user session
# 		cleanup_success = cleanup_user_session(target_user_id)

# 		if cleanup_success:
# 			log_auth_event('session_invalidated', user_id=target_user_id)
# 			return JsonResponse({'status': 'success', 'message': f'Session invalidated for user {target_user_id}'})
# 		else:
# 			return JsonResponse({'error': 'Failed to invalidate session'}, status=500)

# 	except json.JSONDecodeError:
# 		return JsonResponse({'error': 'Invalid JSON'}, status=400)
# 	except Exception as e:
# 		logger.error(f'Session invalidation failed: {str(e)}')
# 		return JsonResponse({'error': 'Session invalidation failed'}, status=500)


# def _test_redis_operations() -> Dict[str, bool]:
# 	"""
# 	Test basic Redis operations for health check

# 	Returns:
# 	    Dictionary with test results
# 	"""
# 	try:
# 		import time

# 		test_key = f'health_test_{int(time.time())}'
# 		test_value = 'test_value'

# 		# Test set/get
# 		set_success = redis_manager.cache.set(test_key, test_value, timeout=60)
# 		get_success = redis_manager.cache.get(test_key) == test_value

# 		# Cleanup
# 		redis_manager.cache.delete(test_key)

# 		return {'set_operation': set_success, 'get_operation': get_success, 'overall': set_success and get_success}
# 	except Exception as e:
# 		logger.error(f'Redis health test failed: {str(e)}')
# 		return {'set_operation': False, 'get_operation': False, 'overall': False, 'error': str(e)}
