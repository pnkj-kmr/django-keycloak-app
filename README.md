# django-keycloak-app
A Django app with keycloak integrated


Key URLs to Test:
🔧 Authentication & Management:

http://localhost:8000/ - Home page with navigation
http://localhost:8000/auth/login/ - Login with Keycloak
http://localhost:8000/auth/status/ - Authentication status (JSON)
http://localhost:8000/auth/user-info/ - User information (JSON)
http://localhost:8000/auth/health/redis/ - System health check
http://localhost:8000/auth/logout/ - Logout

🔒 Protected Areas (Role-based):

http://localhost:8000/api/public/ - Public (no auth)
http://localhost:8000/api/protected/ - Login required
http://localhost:8000/api/dashboard/ - User dashboard
http://localhost:8000/api/staff-area/ - Staff role required
http://localhost:8000/api/admin-area/ - Admin role required
http://localhost:8000/api/manager-area/ - Manager/Admin role

🔌 API Endpoints:

http://localhost:8000/api/api/profile/ - Bearer token required

