# app/user_keycloak/permissions.py
"""
Django REST Framework permissions for Keycloak
"""

import logging
from typing import List, Union
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import View

from .user import KeycloakUser

logger = logging.getLogger('keycloak_auth')


class KeycloakPermission(BasePermission):
	"""
	Base permission class for Keycloak-based permissions
	"""

	def has_permission(self, request: Request, view: View) -> bool:
		"""
		Return True if permission is granted, False otherwise
		"""
		if not hasattr(request, 'user') or not isinstance(request.user, KeycloakUser):
			return False

		return request.user.is_authenticated and request.user.is_active


class HasKeycloakRole(KeycloakPermission):
	"""
	Permission that checks for specific Keycloak roles
	"""

	def __init__(self, roles: Union[str, List[str]], require_all: bool = False):
		if isinstance(roles, str):
			roles = [roles]
		self.required_roles = roles
		self.require_all = require_all

	def has_permission(self, request: Request, view: View) -> bool:
		if not super().has_permission(request, view):
			return False

		user = request.user

		if self.require_all:
			return user.has_all_roles(self.required_roles)
		else:
			return user.has_any_role(self.required_roles)


class HasKeycloakGroup(KeycloakPermission):
	"""
	Permission that checks for specific Keycloak groups
	"""

	def __init__(self, groups: Union[str, List[str]], require_all: bool = False):
		if isinstance(groups, str):
			groups = [groups]
		self.required_groups = groups
		self.require_all = require_all

	def has_permission(self, request: Request, view: View) -> bool:
		if not super().has_permission(request, view):
			return False

		user = request.user
		user_groups = user.groups

		if self.require_all:
			return all(group in user_groups for group in self.required_groups)
		else:
			return any(group in user_groups for group in self.required_groups)


class IsKeycloakAdmin(KeycloakPermission):
	"""
	Permission that checks for admin role
	"""

	def has_permission(self, request: Request, view: View) -> bool:
		if not super().has_permission(request, view):
			return False

		return request.user.has_any_role(['admin', 'superuser'])


class IsKeycloakStaff(KeycloakPermission):
	"""
	Permission that checks for staff role
	"""

	def has_permission(self, request: Request, view: View) -> bool:
		if not super().has_permission(request, view):
			return False

		return request.user.has_any_role(['staff', 'admin', 'superuser'])


class TokenNotExpired(KeycloakPermission):
	"""
	Permission that checks token expiry with buffer
	"""

	def __init__(self, buffer_seconds: int = 300):
		self.buffer_seconds = buffer_seconds

	def has_permission(self, request: Request, view: View) -> bool:
		if not super().has_permission(request, view):
			return False

		user = request.user
		remaining = user.get_token_remaining_time()

		return remaining > self.buffer_seconds


# Permission classes that can be used as decorators
def role_required(*roles, require_all: bool = False):
	"""
	Create a permission class for specific roles
	"""
	return HasKeycloakRole(list(roles), require_all=require_all)


def group_required(*groups, require_all: bool = False):
	"""
	Create a permission class for specific groups
	"""
	return HasKeycloakGroup(list(groups), require_all=require_all)


# Commonly used permission instances
IsAdmin = IsKeycloakAdmin()
IsStaff = IsKeycloakStaff()
HasValidToken = TokenNotExpired()
