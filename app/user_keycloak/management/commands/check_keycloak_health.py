# app/user_keycloak/management/commands/check_keycloak_health.py
"""
Management command to check Keycloak integration health
"""

import requests
from django.core.management.base import BaseCommand
from app.user_keycloak.utils import get_keycloak_config
from app.user_keycloak.redis_util import redis_manager


class Command(BaseCommand):
	help = 'Check Keycloak integration health'

	def handle(self, *args, **options):
		self.stdout.write('🔍 Checking Keycloak integration health...\n')

		# Check configuration
		self.check_configuration()

		# Check Redis connection
		self.check_redis()

		# Check Keycloak connectivity
		self.check_keycloak_connectivity()

		self.stdout.write(self.style.SUCCESS('\n✅ Health check completed!'))

	def check_configuration(self):
		self.stdout.write('📋 Checking configuration...')

		config = get_keycloak_config()
		required_keys = [
			'SERVER_URL',
			'REALM',
			'CLIENT_ID',
			'CLIENT_SECRET',
			'AUTHORIZATION_URL',
			'TOKEN_URL',
			'JWKS_URL',
		]

		missing_keys = [key for key in required_keys if not config.get(key)]

		if missing_keys:
			self.stdout.write(self.style.ERROR(f'❌ Missing configuration keys: {", ".join(missing_keys)}'))
		else:
			self.stdout.write(self.style.SUCCESS('✅ Configuration is complete'))

	def check_redis(self):
		self.stdout.write('📡 Checking Redis connection...')

		try:
			stats = redis_manager.get_redis_stats()
			if 'error' in stats:
				self.stdout.write(self.style.ERROR(f'❌ Redis error: {stats["error"]}'))
			else:
				self.stdout.write(self.style.SUCCESS('✅ Redis is connected'))
				self.stdout.write(f'   Version: {stats.get("redis_version", "unknown")}')
				self.stdout.write(f'   Connected clients: {stats.get("connected_clients", 0)}')
		except Exception as e:
			self.stdout.write(self.style.ERROR(f'❌ Redis connection failed: {str(e)}'))

	def check_keycloak_connectivity(self):
		self.stdout.write('🔐 Checking Keycloak connectivity...')

		config = get_keycloak_config()
		jwks_url = config.get('JWKS_URL')

		if not jwks_url:
			self.stdout.write(self.style.ERROR('❌ JWKS URL not configured'))
			return

		try:
			response = requests.get(jwks_url, timeout=10)
			if response.status_code == 200:
				jwks = response.json()
				key_count = len(jwks.get('keys', []))
				self.stdout.write(self.style.SUCCESS(f'✅ Keycloak is reachable'))
				self.stdout.write(f'   JWKS endpoint: {jwks_url}')
				self.stdout.write(f'   Available keys: {key_count}')
			else:
				self.stdout.write(self.style.ERROR(f'❌ JWKS endpoint returned {response.status_code}'))
		except Exception as e:
			self.stdout.write(self.style.ERROR(f'❌ Cannot reach Keycloak: {str(e)}'))
