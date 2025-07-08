"""
URL configuration for testttt project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

# from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse


def home_view(request):
	user_info = ''
	if hasattr(request, 'user') and request.user and request.user.is_authenticated:
		user_info = f"""
        <div style="background: #d4edda; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
            <h3>👋 Welcome, {request.user.get_full_name() or request.user.username}!</h3>
            <p><strong>Roles:</strong> {', '.join(request.user.roles)}</p>
            <p><strong>Token expires in:</strong> {request.user.get_token_remaining_time()} seconds</p>
        </div>
        """
	return HttpResponse(f"""
   <!DOCTYPE html>
   <html>
   <head>
       <title>Keycloak Auth App - Home</title>
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <style>
           body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }}
           .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
           h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
           .nav-section {{ margin-bottom: 30px; }}
           .nav-section h3 {{ color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
           .nav-links {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }}
           .nav-link {{ display: block; padding: 15px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; text-decoration: none; color: #333; transition: all 0.2s; }}
           .nav-link:hover {{ background: #e9ecef; transform: translateY(-2px); }}
           .nav-link.admin {{ border-left: 4px solid #dc3545; }}
           .nav-link.staff {{ border-left: 4px solid #ffc107; }}
           .nav-link.api {{ border-left: 4px solid #28a745; }}
           .status-info {{ background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
       </style>
   </head>
   <body>
       <div class="container">
           <h1>🔐 Keycloak Authentication Demo</h1>
           
           {user_info}
           
           <div class="nav-section">
               <h3>🔧 Authentication & Status</h3>
               <div class="nav-links">
                   <a href="/auth/login/" class="nav-link">🔑 Login with Keycloak</a>
                   <a href="/auth/status/" class="nav-link">📊 Authentication Status (JSON)</a>
                   <a href="/auth/user-info/" class="nav-link">👤 User Information (JSON)</a>
                   <a href="/auth/health/redis/" class="nav-link">🏥 Redis Health Check</a>
                   <a href="/auth/logout/" class="nav-link">🚪 Logout</a>
               </div>
           </div>
           
           <div class="nav-section">
               <h3>🔒 Protected Areas</h3>
               <div class="nav-links">
                   <a href="/api/public/" class="nav-link">🌍 Public Area (No Auth Required)</a>
                   <a href="/api/protected/" class="nav-link">🔐 Protected Area (Login Required)</a>
                   <a href="/api/dashboard/" class="nav-link">📊 User Dashboard</a>
               </div>
           </div>
           
           <div class="nav-section">
               <h3>👥 Role-Based Access</h3>
               <div class="nav-links">
                   <a href="/api/staff-area/" class="nav-link staff">👔 Staff Area (Staff Role)</a>
                   <a href="/api/manager-area/" class="nav-link staff">👨‍💼 Manager Area (Manager/Admin Role)</a>
                   <a href="/api/admin-area/" class="nav-link admin">🔧 Admin Area (Admin Role Only)</a>
                   <a href="/api/admin-or-manager/" class="nav-link">🎛️ Admin OR Manager (Either Role)</a>
                   <a href="/api/admin-auditor/" class="nav-link admin">🔍 Admin + Auditor (Both Roles Required)</a>
               </div>
           </div>
           
           <div class="nav-section">
               <h3>🔌 API Endpoints</h3>
               <div class="nav-links">
                   <a href="/api/api/profile/" class="nav-link api">👤 API User Profile (Bearer Token)</a>
                   <a href="/auth/test/user/" class="nav-link api">🧪 Test User Backend</a>
               </div>
           </div>
           
           <div class="status-info">
               <h4>📝 Testing Instructions:</h4>
               <ol>
                   <li><strong>Login:</strong> Click "Login with Keycloak" to authenticate</li>
                   <li><strong>Test Roles:</strong> Try accessing different role-based areas</li>
                   <li><strong>API Testing:</strong> Use tools like curl or Postman with Bearer tokens</li>
                   <li><strong>Health Checks:</strong> Monitor Redis and Keycloak connectivity</li>
               </ol>
               <p><em>Note: Role-based areas will show "Access Denied" if you don't have the required roles in Keycloak.</em></p>
           </div>
       </div>
   </body>
   </html>
   """)


urlpatterns = [
	path('', home_view, name='home'),
	# path('admin/', admin.site.urls),
	# package urls
	# path('api/', include('app.api.urls')),
	path('auth/', include('app.user_keycloak.urls')),
	path('api/', include('app.api.urls')),
]
