# Phase 1: Keycloak Setup - Detailed Steps

## **Step 1: Create Keycloak Realm**

### 1.1 Access Keycloak Admin Console
- Navigate to your Keycloak admin console (typically `http://localhost:8080/admin`)
- Login with admin credentials

### 1.2 Create New Realm
```
1. Click "Add realm" button (top-left dropdown)
2. Enter realm name: "django-app" (or your preferred name)
3. Click "Create"
```

### 1.3 Configure Realm Settings
Navigate to **Realm Settings** → **General**:
```
- Display name: "Django Application"
- HTML Display name: "<b>Django App</b>"
- Frontend URL: (leave blank for now)
- Require SSL: "External requests" (for development)
```

Navigate to **Realm Settings** → **Login**:
```
- User registration: OFF (unless you want self-registration)
- Edit username: ON
- Forgot password: ON
- Remember me: ON
- Verify email: OFF (for development)
- Login with email: ON
```

Navigate to **Realm Settings** → **Tokens**:
```
- Default Signature Algorithm: RS256
- Access Token Lifespan: 15 minutes (adjust as needed)
- Access Token Lifespan for Implicit Flow: 15 minutes
- Client login timeout: 30 minutes
- Refresh Token Max Reuse: 0
- SSO Session Idle: 30 minutes
- SSO Session Max: 10 hours
```

## **Step 2: Create Keycloak Client**

### 2.1 Create Client
```
1. Go to "Clients" section
2. Click "Create" button
3. Fill in:
   - Client ID: "django-client"
   - Client Protocol: "openid-connect"
   - Root URL: "http://localhost:8000"
4. Click "Save"
```

### 2.2 Configure Client Settings
Navigate to **Client Settings** → **Settings**:
```
- Name: "Django Application Client"
- Description: "Client for Django application"
- Enabled: ON
- Consent Required: OFF
- Client Protocol: openid-connect
- Access Type: confidential
- Standard Flow Enabled: ON
- Implicit Flow Enabled: OFF
- Direct Access Grants Enabled: ON
- Service Accounts Enabled: ON
- Authorization Enabled: OFF
```

**Valid Redirect URIs:**
```
http://localhost:8000/*
http://localhost:8000/auth/callback/
http://localhost:8000/accounts/login/
```

**Web Origins:**
```
http://localhost:8000
```

**Advanced Settings:**
```
- Proof Key for Code Exchange Code Challenge Method: S256
- Access Token Lifespan: (leave empty to use realm default)
```

### 2.3 Get Client Credentials
Navigate to **Client Settings** → **Credentials**:
```
- Copy "Secret" value (you'll need this for Django)
```

## **Step 3: Configure Roles & Groups**

### 3.1 Create Realm Roles
Navigate to **Roles** → **Realm Roles**:
```
1. Click "Add Role"
2. Create these roles:
   - Role Name: "admin"
   - Description: "Administrator role"
   - Composite: OFF
   
3. Click "Save"
4. Repeat for other roles:
   - "user" (Regular user)
   - "manager" (Manager role)
   - "staff" (Staff role)
```

### 3.2 Create Client Roles (Optional)
Navigate to **Roles** → **Client Roles**:
```
1. Select "django-client" from dropdown
2. Click "Add Role"
3. Create client-specific roles if needed:
   - "django-admin"
   - "django-user"
```

### 3.3 Create Groups (Optional)
Navigate to **Groups**:
```
1. Click "New"
2. Create groups:
   - Name: "Administrators"
   - Click "Save"
   
3. Assign roles to groups:
   - Select "Administrators" group
   - Go to "Role Mappings" tab
   - Assign "admin" role
```

## **Step 4: Create Test Users**

### 4.1 Create Users
Navigate to **Users**:
```
1. Click "Add user"
2. Fill in:
   - Username: "testuser"
   - Email: "test@example.com"
   - First Name: "Test"
   - Last Name: "User"
   - User Enabled: ON
   - Email Verified: ON
3. Click "Save"
```

### 4.2 Set User Password
```
1. Go to "Credentials" tab
2. Set Password: "testpassword"
3. Temporary: OFF
4. Click "Set Password"
```

### 4.3 Assign Roles to User
```
1. Go to "Role Mappings" tab
2. Select roles from "Available Roles"
3. Click "Add selected" to assign roles
```

## **Step 5: Test Configuration**

### 5.1 Test Authentication Flow
```
1. Open new browser tab
2. Navigate to:
   http://localhost:8080/realms/django-app/protocol/openid-connect/auth?client_id=django-client&response_type=code&redirect_uri=http://localhost:8000/auth/callback/&scope=openid

3. Login with test user credentials
4. Should redirect to callback URL (will show error for now - that's expected)
```

### 5.2 Get Realm Configuration
Save these URLs for Django configuration:
```
- Realm URL: http://localhost:8080/realms/django-app
- Auth URL: http://localhost:8080/realms/django-app/protocol/openid-connect/auth
- Token URL: http://localhost:8080/realms/django-app/protocol/openid-connect/token
- UserInfo URL: http://localhost:8080/realms/django-app/protocol/openid-connect/userinfo
- Logout URL: http://localhost:8080/realms/django-app/protocol/openid-connect/logout
- JWKS URL: http://localhost:8080/realms/django-app/protocol/openid-connect/certs
```

## **Configuration Summary**
At the end of Phase 1, you should have:
- ✅ Keycloak realm: "django-app"
- ✅ Client: "django-client" (confidential)
- ✅ Client secret
- ✅ Realm roles: admin, user, manager, staff
- ✅ Test user with password
- ✅ All necessary URLs for Django integration

**Next Step:** We'll move to Phase 2 (Django Configuration) where we'll set up Django to work with this Keycloak configuration.

Ready to proceed to Phase 2?