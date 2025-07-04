#!/bin/bash
# Django-Allauth Keycloak Setup Script

echo "🚀 Setting up Django-Allauth Keycloak Integration..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
    print_status "Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate || source venv/Scripts/activate
print_status "Virtual environment activated"

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing requirements..."
    pip install -r requirements.txt
    print_status "Requirements installed"
else
    print_error "requirements.txt not found!"
    echo "Creating requirements.txt..."
    cat > requirements.txt << EOF
Django>=4.2.0
django-allauth>=0.57.0
djangorestframework>=3.14.0
python-decouple>=3.8
requests>=2.28.0
python-jose[cryptography]>=3.3.0
django-cors-headers>=4.3.0
EOF
    pip install -r requirements.txt
    print_status "Requirements.txt created and installed"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOF
# Django settings
DEBUG=True
SECRET_KEY=django-insecure-change-this-in-production-$(openssl rand -base64 32)

# Keycloak configuration
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=django-app
KEYCLOAK_CLIENT_ID=django-client
KEYCLOAK_CLIENT_SECRET=paste-your-client-secret-here

# Database (if using PostgreSQL)
# DATABASE_URL=postgres://user:password@localhost:5432/dbname

# Email configuration (optional)
# EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EOF
    print_status ".env file created"
    print_warning "Please update KEYCLOAK_CLIENT_SECRET in .env file!"
else
    print_status ".env file already exists"
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p templates/account
mkdir -p templates/authentication
mkdir -p templates/core
mkdir -p static/css
mkdir -p static/js
mkdir -p media
print_status "Directories created"

# Check if manage.py exists
if [ ! -f "manage.py" ]; then
    print_error "manage.py not found! Please run this script from your Django project root."
    exit 1
fi

# Run Django migrations
echo "Running Django migrations..."
python manage.py makemigrations
python manage.py migrate
print_status "Database migrations completed"

# Create sites entry for allauth
echo "Creating site entry for allauth..."
python manage.py shell << EOF
from django.contrib.sites.models import Site
try:
    site = Site.objects.get(pk=1)
    site.domain = 'localhost:8000'
    site.name = 'Django Keycloak Local'
    site.save()
    print("Site updated successfully")
except Site.DoesNotExist:
    Site.objects.create(pk=1, domain='localhost:8000', name='Django Keycloak Local')
    print("Site created successfully")
EOF

# Create social application for Keycloak
echo "Creating Keycloak social application..."
python manage.py shell << EOF
from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
import os
from decouple import config

try:
    app = SocialApp.objects.get(provider='keycloak')
    print("Keycloak social app already exists")
except SocialApp.DoesNotExist:
    app = SocialApp.objects.create(
        provider='keycloak',
        name='Keycloak',
        client_id=config('KEYCLOAK_CLIENT_ID', default='django-client'),
        secret=config('KEYCLOAK_CLIENT_SECRET', default='change-me'),
        settings={
            'KEYCLOAK_URL': config('KEYCLOAK_SERVER_URL', default='http://localhost:8080'),
            'KEYCLOAK_REALM': config('KEYCLOAK_REALM', default='django-app'),
        }
    )
    app.sites.add(Site.objects.get(pk=1))
    print("Keycloak social app created successfully")
EOF

# Create superuser (optional)
echo "Creating superuser..."
python manage.py shell << EOF
from django.contrib.auth.models import User
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print("Superuser created: admin/admin123")
else:
    print("Superuser already exists")
EOF

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput
print_status "Static files collected"

# Final setup summary
echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Setup Summary:"
echo "=================="
print_status "Virtual environment: $(which python)"
print_status "Django version: $(python -c 'import django; print(django.get_version())')"
print_status "Database: SQLite (default)"
print_status "Superuser: admin/admin123"
print_status "Site: localhost:8000"
echo ""
echo "🔧 Next Steps:"
echo "==============="
echo "1. Update your Keycloak client secret in .env file"
echo "2. Make sure Keycloak is running on http://localhost:8080"
echo "3. Start Django development server:"
echo "   python manage.py runserver"
echo ""
echo "🌐 URLs to test:"
echo "=================="
echo "• Home: http://localhost:8000/"
echo "• Login: http://localhost:8000/accounts/login/"
echo "• Admin: http://localhost:8000/admin/"
echo "• API Health: http://localhost:8000/auth/api/health/"
echo "• API Public: http://localhost:8000/api/public/"
echo ""
echo "🔐 Keycloak Setup Required:"
echo "============================"
echo "1. Create realm 'django-app' in Keycloak"
echo "2. Create client 'django-client' in Keycloak"
echo "3. Copy client secret to .env file"
echo "4. Set redirect URIs in Keycloak client:"
echo "   - http://localhost:8000/accounts/keycloak/login/callback/"
echo ""
print_warning "Remember to update KEYCLOAK_CLIENT_SECRET in .env file!"