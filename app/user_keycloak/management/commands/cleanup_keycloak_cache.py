# app/user_keycloak/management/commands/cleanup_keycloak_cache.py
"""
Management command to cleanup Keycloak cache
"""

from django.core.management.base import BaseCommand
from app.user_keycloak.redis_util import redis_manager


class Command(BaseCommand):
	help = 'Cleanup Keycloak authentication cache'

	def add_arguments(self, parser):
		parser.add_argument(
			'--user-id',
			type=str,
			help='Cleanup specific user ID',
		)
		parser.add_argument(
			'--expired-only',
			action='store_true',
			help='Only cleanup expired entries',
		)
		parser.add_argument(
			'--dry-run',
			action='store_true',
			help='Show what would be cleaned up without actually doing it',
		)

	def handle(self, *args, **options):
		user_id = options.get('user_id')
		expired_only = options['expired_only']
		dry_run = options['dry_run']

		if dry_run:
			self.stdout.write(self.style.WARNING('🔍 DRY RUN MODE - No actual cleanup will be performed'))

		if user_id:
			# Cleanup specific user
			self.stdout.write(f'Cleaning up cache for user: {user_id}')
			if not dry_run:
				success = redis_manager.invalidate_user_tokens(user_id)
				if success:
					self.stdout.write(self.style.SUCCESS(f'✅ Cleaned up user {user_id}'))
				else:
					self.stdout.write(self.style.ERROR(f'❌ Failed to cleanup user {user_id}'))
		else:
			# General cleanup
			stats = redis_manager.get_keycloak_cache_stats()
			self.stdout.write('Cache Statistics:')
			for key, value in stats.items():
				self.stdout.write(f'  {key}: {value}')

			if not dry_run and not expired_only:
				# Note: In a real implementation, you'd want to iterate through cache keys
				# and clean up based on TTL or other criteria
				cleanup_stats = redis_manager.cleanup_expired_data()
				self.stdout.write(f'Cleanup completed: {cleanup_stats}')
