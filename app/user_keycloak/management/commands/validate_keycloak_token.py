# app/user_keycloak/management/commands/validate_keycloak_token.py
"""
Management command to validate Keycloak tokens
"""

from django.core.management.base import BaseCommand, CommandError

# from app.user_keycloak.validators import jwt_validator
from app.user_keycloak.validators_pyjwt import jwt_validator
from app.user_keycloak.user import KeycloakUser


class Command(BaseCommand):
	help = 'Validate a Keycloak JWT token'

	def add_arguments(self, parser):
		parser.add_argument('token', type=str, help='JWT token to validate')
		parser.add_argument(
			'--verbose',
			action='store_true',
			help='Show detailed token information',
		)

	def handle(self, *args, **options):
		token = options['token']
		verbose = options['verbose']

		try:
			# Validate token
			payload = jwt_validator.validate_token(token)
			user_info = jwt_validator.extract_user_info(payload)

			self.stdout.write(self.style.SUCCESS(f'✅ Token is valid!'))

			if verbose:
				self.stdout.write('\nToken Details:')
				self.stdout.write(f'User ID: {user_info.get("sub")}')
				self.stdout.write(f'Username: {user_info.get("preferred_username")}')
				self.stdout.write(f'Email: {user_info.get("email")}')
				self.stdout.write(f'Roles: {", ".join(user_info.get("roles", []))}')
				self.stdout.write(f'Groups: {", ".join(user_info.get("groups", []))}')
				self.stdout.write(f'Expires at: {payload.get("exp")}')
				self.stdout.write(f'Issued at: {payload.get("iat")}')

		except Exception as e:
			raise CommandError(f'❌ Token validation failed: {str(e)}')
