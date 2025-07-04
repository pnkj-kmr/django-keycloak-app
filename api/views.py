from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib import messages


def home(request):
	"""Home page view - shows authentication status"""
	context = {'user': request.user, 'is_authenticated': request.user.is_authenticated, 'page_title': 'Home'}
	return render(request, 'home.html', context)


@login_required
def profile(request):
	"""User profile page - requires authentication"""
	social_accounts = None
	if request.user.is_authenticated:
		try:
			social_accounts = request.user.socialaccount_set.all()
		except:
			social_accounts = None

	context = {'user': request.user, 'social_accounts': social_accounts, 'page_title': 'Profile'}
	return render(request, 'profile.html', context)


def login_success(request):
	"""Optional view for successful login redirect"""
	messages.success(request, 'You have successfully logged in!')
	return render(request, 'home.html', {'user': request.user})
