# """
# API ViewSets for Keycloak integration
# """

# import logging
# import time
# from typing import Dict, Any
# from rest_framework import status, viewsets, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from rest_framework.request import Request
# from django.utils.decorators import method_decorator
# from django.views.decorators.cache import cache_page

# from .permissions import IsKeycloakAdmin, IsKeycloakStaff, HasKeycloakRole
# from .redis_util import redis_manager
# from .utils import log_auth_event

# logger = logging.getLogger('keycloak_auth')


# class AuthenticationViewSet(viewsets.ViewSet):
# 	"""
# 	API endpoints for authentication management
# 	"""

# 	permission_classes = [permissions.IsAuthenticated]

# 	@action(detail=False, methods=['get'])
# 	def status(self, request: Request) -> Response:
# 		"""
# 		Get current authentication status
# 		"""
# 		user = request.user

# 		return Response(
# 			{
# 				'authenticated': True,
# 				'user': {
# 					'id': user.id,
# 					'username': user.username,
# 					'email': user.email,
# 					'roles': user.roles,
# 					'groups': user.groups,
# 				},
# 				'token': {
# 					'expires_at': user.get_token_expiry_time(),
# 					'remaining_seconds': user.get_token_remaining_time(),
# 					'expired': user.is_token_expired(),
# 				},
# 			}
# 		)

# 	@action(detail=False, methods=['post'])
# 	def refresh(self, request: Request) -> Response:
# 		"""
# 		Refresh access token
# 		"""
# 		try:
# 			user = request.user
# 			refresh_token = user.get_refresh_token()

# 			if not refresh_token:
# 				return Response({'error': 'No refresh token available'}, status=status.HTTP_400_BAD_REQUEST)

# 			# Refresh token using Keycloak client
# 			from .client import keycloak_client

# 			new_tokens = keycloak_client.refresh_access_token(refresh_token)

# 			# Update user tokens
# 			user.tokens.update(new_tokens)

# 			# Update Redis cache
# 			redis_manager.update_user_tokens(user.id, user.tokens, new_tokens.get('expires_in', 3600))

# 			log_auth_event('api_token_refreshed', user_id=user.id)

# 			return Response(
# 				{
# 					'access_token': new_tokens['access_token'],
# 					'expires_in': new_tokens.get('expires_in'),
# 					'token_type': 'Bearer',
# 				}
# 			)

# 		except Exception as e:
# 			logger.error(f'Token refresh error: {str(e)}')
# 			return Response({'error': 'Token refresh failed'}, status=status.HTTP_400_BAD_REQUEST)

# 	@action(detail=False, methods=['post'])
# 	def logout(self, request: Request) -> Response:
# 		"""
# 		Logout user
# 		"""
# 		try:
# 			user = request.user

# 			# Revoke refresh token with Keycloak
# 			refresh_token = user.get_refresh_token()
# 			if refresh_token:
# 				from .client import keycloak_client

# 				keycloak_client.logout_user(refresh_token)

# 			# Clear Redis cache
# 			redis_manager.invalidate_user_tokens(user.id)

# 			log_auth_event('api_logout', user_id=user.id)

# 			return Response({'message': 'Logged out successfully'})

# 		except Exception as e:
# 			logger.error(f'Logout error: {str(e)}')
# 			return Response({'error': 'Logout failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class AdminViewSet(viewsets.ViewSet):
# 	"""
# 	Admin API endpoints
# 	"""

# 	permission_classes = [IsKeycloakAdmin]

# 	@action(detail=False, methods=['get'])
# 	@method_decorator(cache_page(300))  # Cache for 5 minutes
# 	def system_status(self, request: Request) -> Response:
# 		"""
# 		Get system status and health
# 		"""
# 		try:
# 			# Get various system metrics
# 			redis_stats = redis_manager.get_redis_stats()
# 			# perf_metrics = perf_monitor.get_metrics()

# 			return Response(
# 				{
# 					'status': 'healthy',
# 					'redis': redis_stats,
# 					# 'cache': cache_stats,
# 					# 'performance': {
# 					# 	'metrics': perf_metrics,
# 					# 	'slow_operations': perf_monitor.get_top_slow_operations(5),
# 					# },
# 					# 'timestamp': cache_stats.get('timestamp'),
# 				}
# 			)

# 		except Exception as e:
# 			logger.error(f'System status error: {str(e)}')
# 			return Response({'status': 'error', 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 	@action(detail=False, methods=['post'])
# 	def invalidate_user_cache(self, request: Request) -> Response:
# 		"""
# 		Invalidate cache for a specific user
# 		"""
# 		user_id = request.data.get('user_id')
# 		if not user_id:
# 			return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

# 		try:
# 			# Invalidate user cache
# 			success = redis_manager.invalidate_user_tokens(user_id)
# 			# cache_manager.invalidate_user_permissions(user_id)

# 			log_auth_event('admin_cache_invalidated', user_id=request.user.id, details={'target_user': user_id})

# 			return Response({'success': success, 'message': f'Cache invalidated for user {user_id}'})

# 		except Exception as e:
# 			logger.error(f'Cache invalidation error: {str(e)}')
# 			return Response({'error': 'Cache invalidation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 	# @action(detail=False, methods=['post'])
# 	# def clear_cache_pattern(self, request: Request) -> Response:
# 	# 	"""
# 	# 	Clear cache entries matching a pattern
# 	# 	"""
# 	# 	pattern = request.data.get('pattern')
# 	# 	if not pattern:
# 	# 		return Response({'error': 'pattern is required'}, status=status.HTTP_400_BAD_REQUEST)

# 	# 	try:
# 	# 		count = cache_manager.invalidate_pattern(pattern)

# 	# 		log_auth_event(
# 	# 			'admin_cache_pattern_cleared', user_id=request.user.id, details={'pattern': pattern, 'count': count}
# 	# 		)

# 	# 		return Response({'cleared_entries': count, 'pattern': pattern})

# 	# 	except Exception as e:
# 	# 		logger.error(f'Pattern cache clear error: {str(e)}')
# 	# 		return Response({'error': 'Cache clear failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class UserManagementViewSet(viewsets.ViewSet):
# 	"""
# 	User management API endpoints
# 	"""

# 	permission_classes = [IsKeycloakStaff]

# 	@action(detail=False, methods=['get'])
# 	def active_users(self, request: Request) -> Response:
# 		"""
# 		Get list of currently active users
# 		"""
# 		try:
# 			# Get active users from Redis
# 			active_users = []

# 			# This would require implementing a way to track active users
# 			# For now, return placeholder data

# 			return Response({'active_users': active_users, 'count': len(active_users), 'timestamp': int(time.time())})

# 		except Exception as e:
# 			logger.error(f'Active users error: {str(e)}')
# 			return Response({'error': 'Failed to get active users'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 	@action(detail=True, methods=['get'])
# 	def user_sessions(self, request: Request, pk: str = None) -> Response:
# 		"""
# 		Get session information for a specific user
# 		"""
# 		try:
# 			# Check if user has permission to view this user's data
# 			if not request.user.has_role('admin') and request.user.id != pk:
# 				return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

# 			# Get user session data
# 			user_tokens = redis_manager.get_user_tokens(pk)
# 			user_info = redis_manager.get_cached_user_info(pk)

# 			if not user_tokens:
# 				return Response({'error': 'User not found or not active'}, status=status.HTTP_404_NOT_FOUND)

# 			return Response(
# 				{
# 					'user_id': pk,
# 					'session_active': True,
# 					'token_expires_at': user_tokens.get('expires_at'),
# 					'login_time': user_tokens.get('issued_at'),
# 					'user_info': {
# 						'username': user_info.get('preferred_username'),
# 						'email': user_info.get('email'),
# 						'roles': user_info.get('roles', []),
# 					},
# 				}
# 			)

# 		except Exception as e:
# 			logger.error(f'User sessions error: {str(e)}')
# 			return Response({'error': 'Failed to get user sessions'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
