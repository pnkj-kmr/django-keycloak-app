# app/user_keycloak/middleware.py
"""
Enhanced Keycloak JWT authentication middleware with real validation - Phase 3
"""

import logging
from typing import Optional, Callable
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect

import hmac
import hashlib
import time

from .exceptions import (
	TokenValidationError,
	TokenExpiredError,
	InvalidTokenError,
	TokenBlacklistedError,
	KeycloakConnectionError,
	RedisConnectionError,
	SessionExpiredError,
)
from .redis_util import redis_manager
from .user import KeycloakUser

# from .validators import jwt_validator
from .validators_pyjwt import jwt_validator
from .utils import log_auth_event

logger = logging.getLogger('keycloak_auth')


class KeycloakAuthenticationMiddleware(MiddlewareMixin):
	"""
	Production-ready middleware for Keycloak JWT authentication with real validation
	"""

	def __init__(self, get_response: Callable):
		self.get_response = get_response
		self.keycloak_config = getattr(settings, 'KEYCLOAK_CONFIG', {})

		# URLs that don't require authentication
		self.exempt_urls = [
			'/auth/login/',
			'/auth/callback/',
			'/auth/logout/',
			'/auth/refresh/',
			'/auth/health/',
			'/auth/status/',
			'/static/',
			'/media/',
			'/favicon.ico',
			'/robots.txt',
		]

		# API endpoints that should return JSON errors
		self.api_prefixes = ['/api/', '/auth/']

		# Configuration options
		self.validate_every_request = self.keycloak_config.get('VALIDATE_EVERY_REQUEST', False)
		self.auto_refresh_threshold = self.keycloak_config.get('AUTO_REFRESH_THRESHOLD', 300)  # 5 minutes

		super().__init__(get_response)

	def __call__(self, request):
		"""Main middleware processing"""
		# Process request for authentication
		auth_response = self.process_request(request)
		if auth_response:
			return auth_response

		# Get response from view
		response = self.get_response(request)

		# Process response (add headers, etc.)
		return self.process_response(request, response)

	def process_request(self, request) -> Optional[HttpResponse]:
		"""
		Process incoming request for authentication with real JWT validation
		"""
		# Skip authentication for exempt URLs
		if self._is_exempt_url(request.path):
			logger.debug(f'Skipping auth for exempt URL: {request.path}')
			request.user = None
			return None

		try:
			# Check Redis connection first
			if not self._check_redis_connection():
				return self._handle_redis_error(request)

			# Try multiple authentication methods in order of preference
			user = None
			auth_method = None

			# Method 1: Session-based authentication (for web requests)
			user_id = request.session.get('user_id')
			if user_id and request.session.get('authenticated'):
				user = self._get_user_from_session(request, user_id)
				if user:
					auth_method = 'session'

			# Method 2: Bearer token authentication (for API requests)
			if not user:
				auth_header = request.META.get('HTTP_AUTHORIZATION', '')
				if auth_header.startswith('Bearer '):
					access_token = auth_header[7:]
					user = self._authenticate_with_token(request, access_token)
					if user:
						auth_method = 'bearer_token'

			# Method 3: Token from query parameters (fallback, less secure)
			if not user and request.GET.get('access_token'):
				access_token = request.GET.get('access_token')
				user = self._authenticate_with_token(request, access_token)
				if user:
					auth_method = 'query_token'
					logger.warning('Token authentication via query parameter - consider using Authorization header')

			if user:
				request.user = user
				request.auth_method = auth_method
				logger.debug(f'Authenticated user {user.username} via {auth_method}')
				return None

			# No valid authentication found
			logger.debug(f'No valid authentication for {request.path}')
			return self._handle_unauthenticated(request)

		except RedisConnectionError as e:
			logger.error(f'Redis connection error: {str(e)}')
			return self._handle_redis_error(request)

		except Exception as e:
			logger.error(f'Unexpected auth error for {request.path}: {str(e)}')
			return self._handle_auth_error(request)

	def _get_user_from_session(self, request, user_id: str) -> Optional[KeycloakUser]:
		"""
		Get user from session-based authentication with token validation and refresh
		"""
		try:
			# Get user data from Redis
			user_tokens = redis_manager.get_user_tokens(user_id)
			user_info = redis_manager.get_cached_user_info(user_id)

			if not user_tokens or not user_info:
				logger.warning(f'No cached data found for user {user_id}')
				self._cleanup_invalid_session(request)
				return None

			# Create user object
			user = KeycloakUser(user_id, user_tokens, user_info)

			# Check if token is expired or expires soon
			if user.is_token_expired():
				logger.info(f'Token expired for user {user_id}')

				# Try to refresh token automatically
				if self._attempt_token_refresh(user):
					logger.info(f'Successfully auto-refreshed token for user {user_id}')
					# Update Redis with refreshed tokens
					redis_manager.update_user_tokens(user_id, user.tokens, user.get_token_remaining_time())
					redis_manager.cache_user_info(user_id, user.user_info, 3600)
				else:
					logger.warning(f'Failed to refresh token for user {user_id}')
					self._cleanup_invalid_session(request)
					return None

			# Auto-refresh if token expires soon
			elif user.get_token_remaining_time() <= self.auto_refresh_threshold:
				logger.info(f'Token expires soon for user {user_id}, attempting refresh')
				if self._attempt_token_refresh(user):
					redis_manager.update_user_tokens(user_id, user.tokens, user.get_token_remaining_time())
					logger.info(f'Proactively refreshed token for user {user_id}')

			# Validate token with Keycloak if configured to do so
			if self.validate_every_request:
				try:
					jwt_validator.validate_token(user.get_access_token())
					logger.debug(f'Token validation successful for user {user_id}')
				except TokenValidationError as e:
					logger.warning(f'Token validation failed for user {user_id}: {str(e)}')
					self._cleanup_invalid_session(request)
					return None

			log_auth_event('session_authenticated', user_id=user_id, details={'path': request.path})

			return user

		except Exception as e:
			logger.error(f'Error getting user from session: {str(e)}')
			self._cleanup_invalid_session(request)
			return None

	def _authenticate_with_token(self, request, access_token: str) -> Optional[KeycloakUser]:
		"""
		Authenticate using Bearer token (for API requests) with full validation
		"""
		try:
			# Validate token and create user
			user = KeycloakUser.from_access_token(access_token)

			# Cache user data in Redis for future requests
			token_remaining = user.get_token_remaining_time()
			if token_remaining > 0:
				redis_manager.store_user_tokens(user.id, user.tokens, token_remaining)
				redis_manager.cache_user_info(user.id, user.user_info, min(3600, token_remaining))

			log_auth_event(
				'token_authenticated',
				user_id=user.id,
				details={'path': request.path, 'token_remaining': token_remaining},
			)

			return user

		except TokenExpiredError:
			logger.debug('Bearer token has expired')
			return None
		except (TokenValidationError, InvalidTokenError) as e:
			logger.debug(f'Bearer token validation failed: {str(e)}')
			return None
		except TokenBlacklistedError:
			logger.warning('Bearer token is blacklisted')
			return None
		except Exception as e:
			logger.error(f'Error authenticating with token: {str(e)}')
			return None

	def _attempt_token_refresh(self, user: KeycloakUser) -> bool:
		"""
		Attempt to refresh user's access token

		Args:
		    user: KeycloakUser instance

		Returns:
		    True if refresh successful, False otherwise
		"""
		try:
			refresh_token = user.get_refresh_token()
			if not refresh_token:
				logger.debug(f'No refresh token available for user {user.id}')
				return False

			# Import here to avoid circular imports
			from .client import keycloak_client

			# Refresh tokens with Keycloak
			new_token_data = keycloak_client.refresh_access_token(refresh_token)

			# Update user tokens
			user.tokens.update(
				{
					'access_token': new_token_data['access_token'],
					'refresh_token': new_token_data.get('refresh_token', refresh_token),
					'expires_at': new_token_data.get('expires_at'),
					'expires_in': new_token_data.get('expires_in', 3600),
					'issued_at': new_token_data.get('issued_at'),
				}
			)

			# Validate new token and update user info
			new_user = KeycloakUser.from_access_token(new_token_data['access_token'])
			user.user_info = new_user.user_info
			user.roles = new_user.roles
			user.groups = new_user.groups

			log_auth_event('token_auto_refreshed', user_id=user.id)
			return True

		except Exception as e:
			logger.error(f'Token refresh failed for user {user.id}: {str(e)}')
			return False

	def _cleanup_invalid_session(self, request):
		"""Clean up invalid session data"""
		user_id = request.session.get('user_id')
		if user_id:
			redis_manager.invalidate_user_tokens(user_id)
		request.session.flush()
		logger.debug(f'Cleaned up invalid session for user {user_id}')

	def _check_redis_connection(self) -> bool:
		"""Check if Redis is available"""
		try:
			redis_stats = redis_manager.get_redis_stats()
			return 'error' not in redis_stats
		except Exception:
			return False

	def _is_exempt_url(self, path: str) -> bool:
		"""Check if URL path is exempt from authentication"""
		return any(path.startswith(exempt_path) for exempt_path in self.exempt_urls)

	def _is_api_request(self, request) -> bool:
		"""Check if request is for API endpoint"""
		return any(request.path.startswith(prefix) for prefix in self.api_prefixes)

	def process_response(self, request, response: HttpResponse) -> HttpResponse:
		"""
		Process outgoing response to add auth-related headers and handle token refresh
		"""
		# Add user info to response headers for debugging
		if hasattr(request, 'user') and request.user:
			response['X-Authenticated-User'] = getattr(request.user, 'username', 'unknown')
			response['X-User-ID'] = getattr(request.user, 'id', 'unknown')
			response['X-User-Roles'] = ','.join(getattr(request.user, 'roles', []))
			response['X-Auth-Method'] = getattr(request, 'auth_method', 'unknown')

			# Add token expiry info for API clients
			if self._is_api_request(request):
				token_remaining = request.user.get_token_remaining_time()
				response['X-Token-Expires-In'] = str(token_remaining)

				# Add refresh hint if token expires soon
				if token_remaining <= 600:  # 10 minutes
					response['X-Token-Refresh-Hint'] = 'true'

		# Add CORS headers for API endpoints if needed
		if self._is_api_request(request):
			response['Access-Control-Allow-Credentials'] = 'true'
			response['X-Auth-Provider'] = 'keycloak'
			response['Access-Control-Expose-Headers'] = 'X-Token-Expires-In,X-Token-Refresh-Hint'

		return response

	# Error handling methods
	def _handle_unauthenticated(self, request) -> HttpResponse:
		"""Handle requests without authentication"""
		log_auth_event('unauthenticated_access', details={'path': request.path})

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Authentication required',
					'error_code': 'UNAUTHENTICATED',
					'login_url': '/auth/login/',
					'details': 'Please provide a valid access token via Authorization header',
				},
				status=401,
			)

		# For web requests, redirect to login with 'next' parameter
		login_url = f'/auth/login/?next={request.path}'
		return redirect(login_url)

	def _handle_session_expired(self, request) -> HttpResponse:
		"""Handle expired user sessions"""
		user_id = request.session.get('user_id')
		log_auth_event('session_expired', user_id=user_id, details={'path': request.path})

		# Clear session
		request.session.flush()

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Session expired',
					'error_code': 'SESSION_EXPIRED',
					'login_url': '/auth/login/',
					'details': 'Your session has expired. Please login again.',
				},
				status=401,
			)

		return redirect('/auth/login/')

	def _handle_expired_token(self, request, user_id: str) -> HttpResponse:
		"""Handle expired authentication tokens"""
		log_auth_event('token_expired', user_id=user_id, details={'path': request.path})

		# Clear expired data
		redis_manager.invalidate_user_tokens(user_id)
		request.session.flush()

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Token expired',
					'error_code': 'TOKEN_EXPIRED',
					'login_url': '/auth/login/',
					'details': 'Your access token has expired. Please refresh or login again.',
				},
				status=401,
			)

		return redirect('/auth/login/')

	def _handle_invalid_token(self, request, user_id: str) -> HttpResponse:
		"""Handle invalid authentication tokens"""
		log_auth_event('invalid_token', user_id=user_id, details={'path': request.path})

		# Clear invalid data
		redis_manager.invalidate_user_tokens(user_id)
		request.session.flush()

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Invalid authentication token',
					'error_code': 'INVALID_TOKEN',
					'login_url': '/auth/login/',
					'details': 'The provided token is invalid or malformed.',
				},
				status=401,
			)

		return redirect('/auth/login/')

	def _handle_blacklisted_token(self, request, user_id: str) -> HttpResponse:
		"""Handle blacklisted tokens"""
		log_auth_event('blacklisted_token', user_id=user_id, details={'path': request.path})

		# Clear blacklisted data
		redis_manager.invalidate_user_tokens(user_id)
		request.session.flush()

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Token has been revoked',
					'error_code': 'TOKEN_REVOKED',
					'login_url': '/auth/login/',
					'details': 'This token has been revoked and is no longer valid.',
				},
				status=401,
			)

		return redirect('/auth/login/')

	def _handle_redis_error(self, request) -> HttpResponse:
		"""Handle Redis connection errors"""
		logger.error('Redis connection failed - authentication service unavailable')

		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Authentication service temporarily unavailable',
					'error_code': 'SERVICE_UNAVAILABLE',
					'retry_after': 30,
					'details': 'The authentication cache is temporarily unavailable.',
				},
				status=503,
			)

		return HttpResponse(
			"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Service Unavailable</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
                    .error-container { max-width: 600px; margin: 0 auto; }
                    .retry-btn { 
                        background: #007bff; color: white; padding: 10px 20px; 
                        text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h1>🔧 Authentication Service Unavailable</h1>
                    <p>The authentication service is temporarily unavailable. Please try again in a few moments.</p>
                    <a href="javascript:window.location.reload()" class="retry-btn">Retry</a>
                </div>
            </body>
            </html>
            """,
			status=503,
			content_type='text/html',
		)

	def _handle_auth_error(self, request) -> HttpResponse:
		"""Handle unexpected authentication errors"""
		if self._is_api_request(request):
			return JsonResponse(
				{
					'error': 'Authentication error occurred',
					'error_code': 'AUTH_ERROR',
					'details': 'An unexpected error occurred during authentication.',
				},
				status=500,
			)

		return HttpResponse(
			"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Error</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
                    .error-container { max-width: 600px; margin: 0 auto; }
                    .login-btn { 
                        background: #007bff; color: white; padding: 10px 20px; 
                        text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h1>🔐 Authentication Error</h1>
                    <p>An authentication error occurred. Please try logging in again.</p>
                    <a href="/auth/login/" class="login-btn">Login</a>
                </div>
            </body>
            </html>
            """,
			status=500,
			content_type='text/html',
		)


class KeycloakPermissionMiddleware(MiddlewareMixin):
	"""
	Optional middleware for role-based access control
	Apply this after KeycloakAuthenticationMiddleware
	"""

	def __init__(self, get_response: Callable):
		self.get_response = get_response

		# URL patterns that require specific roles
		self.role_requirements = getattr(
			settings,
			'KEYCLOAK_ROLE_REQUIREMENTS',
			{
				'/admin/': ['admin'],
				'/staff/': ['staff', 'admin'],
				'/api/admin/': ['admin'],
			},
		)

		super().__init__(get_response)

	def __call__(self, request):
		# Check role requirements before processing request
		auth_response = self.process_request(request)
		if auth_response:
			return auth_response

		response = self.get_response(request)
		return response

	def process_request(self, request) -> Optional[HttpResponse]:
		"""Check if user has required roles for the requested path"""

		# Skip if user is not authenticated
		if not hasattr(request, 'user') or not request.user:
			return None

		# Check role requirements
		for path_pattern, required_roles in self.role_requirements.items():
			if request.path.startswith(path_pattern):
				if not request.user.has_any_role(required_roles):
					log_auth_event(
						'insufficient_permissions',
						user_id=request.user.id,
						details={
							'path': request.path,
							'required_roles': required_roles,
							'user_roles': request.user.roles,
						},
					)

					if request.path.startswith('/api/'):
						return JsonResponse(
							{
								'error': 'Insufficient permissions',
								'error_code': 'FORBIDDEN',
								'required_roles': required_roles,
								'your_roles': request.user.roles,
							},
							status=403,
						)
					else:
						return HttpResponse(
							"""
                            <!DOCTYPE html>
                            <html>
                            <head><title>Access Denied</title></head>
                            <body style="font-family: Arial; text-align: center; margin: 50px;">
                                <h1>🚫 Access Denied</h1>
                                <p>You don't have permission to access this resource.</p>
                                <p>Required roles: """
							+ ', '.join(required_roles)
							+ """</p>
                                <p>Your roles: """
							+ ', '.join(request.user.roles)
							+ """</p>
                                <a href="/">Go Home</a>
                            </body>
                            </html>
                            """,
							status=403,
						)

		return None


class SecurityHeadersMiddleware(MiddlewareMixin):
	"""
	Add security headers to all responses
	"""

	def __init__(self, get_response):
		self.get_response = get_response
		super().__init__(get_response)

	def __call__(self, request):
		response = self.get_response(request)

		# Content Security Policy
		csp = [
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data: https:",
			"font-src 'self'",
			"connect-src 'self' " + settings.KEYCLOAK_CONFIG.get('SERVER_URL', ''),
			"frame-ancestors 'none'",
		]
		response['Content-Security-Policy'] = '; '.join(csp)

		# Additional security headers
		response['X-Content-Type-Options'] = 'nosniff'
		response['X-Frame-Options'] = 'DENY'
		response['X-XSS-Protection'] = '1; mode=block'
		response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
		response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

		# Remove server information
		if 'Server' in response:
			del response['Server']

		return response


class RequestLimitingMiddleware(MiddlewareMixin):
	"""
	Rate limiting middleware for authentication endpoints
	"""

	def __init__(self, get_response):
		self.get_response = get_response
		self.redis_client = redis_manager.get_redis_client()
		super().__init__(get_response)

	def __call__(self, request):
		# Check rate limits for sensitive endpoints
		if self._is_sensitive_endpoint(request.path):
			if not self._check_rate_limit(request):
				return JsonResponse(
					{'error': 'Rate limit exceeded', 'error_code': 'RATE_LIMITED', 'retry_after': 60}, status=429
				)

		response = self.get_response(request)
		return response

	def _is_sensitive_endpoint(self, path: str) -> bool:
		"""Check if endpoint requires rate limiting"""
		sensitive_paths = [
			'/auth/login/',
			'/auth/callback/',
			'/auth/refresh/',
		]
		return any(path.startswith(p) for p in sensitive_paths)

	def _check_rate_limit(self, request) -> bool:
		"""Check if request is within rate limits"""
		try:
			# Get client IP
			client_ip = self._get_client_ip(request)

			# Rate limit key
			key = f'rate_limit:{request.path}:{client_ip}'

			# Check current count
			current = self.redis_client.get(key)
			if current is None:
				# First request
				self.redis_client.setex(key, 300, 1)  # 5 minutes window
				return True

			current = int(current)
			if current >= 10:  # Max 10 requests per 5 minutes
				return False

			# Increment counter
			self.redis_client.incr(key)
			return True

		except Exception as e:
			logger.error(f'Rate limiting error: {e}')
			return True  # Allow request if rate limiting fails

	def _get_client_ip(self, request) -> str:
		"""Get client IP address"""
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for:
			return x_forwarded_for.split(',')[0].strip()
		return request.META.get('REMOTE_ADDR', '')


class RequestSigningMiddleware(MiddlewareMixin):
	"""
	Verify request signatures for high-security API endpoints
	"""

	def __init__(self, get_response):
		self.get_response = get_response
		self.secret_key = settings.SECRET_KEY.encode()
		super().__init__(get_response)

	def __call__(self, request):
		# Check signature for admin API endpoints
		if self._requires_signature(request.path):
			if not self._verify_signature(request):
				return JsonResponse(
					{'error': 'Invalid request signature', 'error_code': 'INVALID_SIGNATURE'}, status=401
				)

		response = self.get_response(request)
		return response

	def _requires_signature(self, path: str) -> bool:
		"""Check if endpoint requires request signing"""
		signed_paths = [
			'/auth/admin/',
			'/auth/invalidate-session/',
		]
		return any(path.startswith(p) for p in signed_paths)

	def _verify_signature(self, request) -> bool:
		"""Verify request signature"""
		try:
			# Get signature from header
			signature = request.META.get('HTTP_X_SIGNATURE')
			timestamp = request.META.get('HTTP_X_TIMESTAMP')

			if not signature or not timestamp:
				return False

			# Check timestamp (5 minute window)
			current_time = int(time.time())
			request_time = int(timestamp)
			if abs(current_time - request_time) > 300:
				return False

			# Build message to sign
			message = f'{request.method}:{request.path}:{timestamp}:{request.body.decode()}'

			# Calculate expected signature
			expected_signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).hexdigest()

			# Compare signatures
			return hmac.compare_digest(signature, expected_signature)

		except Exception as e:
			logger.error(f'Signature verification error: {e}')
			return False
