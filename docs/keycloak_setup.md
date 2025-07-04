Great! Let's set up Keycloak for your Django integration step by step. I'll guide you through the Admin Console.

## Step 1: Create a Realm for Your Django Application

### 1.1 Access Admin Console
- Go to: http://localhost:8080/admin
- Login with: admin / admin

### 1.2 Create New Realm
1. **Click on the dropdown** next to "Keycloak" (top-left corner)
2. **Click "Create Realm"**
3. **Fill in the details:**
   - **Realm name**: `django-app` (or your preferred name)
   - **Display name**: `Django Application`
   - **Enabled**: ✅ (checked)
4. **Click "Create"**

You should now see "django-app" in the realm dropdown.

---

## Step 2: Create a Client for Django OAuth2/OIDC

### 2.1 Navigate to Clients
1. **In the left sidebar**, click **"Clients"**
2. **Click "Create client"**

### 2.2 General Settings
1. **Client type**: `OpenID Connect`
2. **Client ID**: `django-client`
3. **Name**: `Django Application Client`
4. **Description**: `OAuth2/OIDC client for Django application`
5. **Click "Next"**

### 2.3 Capability Config
1. **Client authentication**: ✅ **ON** (This makes it a confidential client)
2. **Authorization**: ✅ **ON** (Enable if you need fine-grained permissions)
3. **Standard flow**: ✅ **ON** (Authorization Code Flow)
4. **Direct access grants**: ✅ **ON** (For API access)
5. **Service accounts roles**: ✅ **ON** (For service-to-service auth)
6. **Click "Next"**

### 2.4 Login Settings
1. **Root URL**: `http://localhost:8000`
2. **Home URL**: `http://localhost:8000`
3. **Valid redirect URIs**: 
   ```
   http://localhost:8000/auth/callback/
   http://localhost:8000/accounts/keycloak/login/callback/
   ```
4. **Valid post logout redirect URIs**: 
   ```
   http://localhost:8000/
   http://localhost:8000/accounts/logout/
   ```
5. **Web origins**: `http://localhost:8000`
6. **Click "Save"**

---

## Step 3: Configure Client Settings

### 3.1 Get Client Credentials
1. **Go to "Credentials" tab**
2. **Copy the "Client secret"** - you'll need this for Django
3. **Save it somewhere safe** (e.g., `client_secret_here`)

### 3.2 Configure Advanced Settings
1. **Go to "Settings" tab**
2. **Scroll down to "Advanced"**
3. **Access Token Lifespan**: `5 minutes` (or as needed)
4. **Client Session Idle**: `30 minutes`
5. **Client Session Max**: `12 hours`
6. **Click "Save"**

### 3.3 Configure Client Scopes (Optional)
1. **Go to "Client scopes" tab**
2. **Default scopes should include:**
   - `openid`
   - `profile`
   - `email`
   - `roles`

---

## Step 4: Set up User Registration/Login Flows

### 4.1 Enable User Registration
1. **In left sidebar**, click **"Realm settings"**
2. **Go to "Login" tab**
3. **Enable these options:**
   - **User registration**: ✅ **ON**
   - **Forgot password**: ✅ **ON**
   - **Remember me**: ✅ **ON**
   - **Email as username**: ✅ **ON** (optional, but recommended)
4. **Click "Save"**

### 4.2 Configure Email Settings (Optional but Recommended)
1. **Go to "Email" tab**
2. **Fill in SMTP settings:**
   ```
   Host: smtp.gmail.com (or your SMTP server)
   Port: 587
   From: noreply@yourdomain.com
   Enable StartTLS: ✅
   Username: your-email@gmail.com
   Password: your-app-password
   ```
3. **Click "Save"**
4. **Click "Test connection"** to verify

### 4.3 Create Test User
1. **In left sidebar**, click **"Users"**
2. **Click "Create new user"**
3. **Fill in details:**
   - **Username**: `testuser`
   - **Email**: `test@example.com`
   - **First name**: `Test`
   - **Last name**: `User`
   - **Email verified**: ✅ **ON**
   - **Enabled**: ✅ **ON**
4. **Click "Create"**

### 4.4 Set Test User Password
1. **Click on the created user**
2. **Go to "Credentials" tab**
3. **Click "Set password"**
4. **Enter password**: `testpass123`
5. **Temporary**: ❌ **OFF**
6. **Click "Save"**

---

## Step 5: Get Configuration Details for Django## Step 6: Test Your Configuration
```
# Keycloak Server Configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8080'
KEYCLOAK_REALM = 'django-app'
KEYCLOAK_CLIENT_ID = 'django-client'
KEYCLOAK_CLIENT_SECRET = 'your-client-secret-here'  # Get this from Keycloak Admin Console

# OAuth2/OIDC URLs (auto-generated based on above)
KEYCLOAK_BASE_URL = f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}'
KEYCLOAK_AUTH_URL = f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/auth'
KEYCLOAK_TOKEN_URL = f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/token'
KEYCLOAK_USERINFO_URL = f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/userinfo'
KEYCLOAK_JWKS_URL = f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/certs'
KEYCLOAK_LOGOUT_URL = f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/logout'

# Well-known configuration endpoint
KEYCLOAK_WELL_KNOWN_URL = f'{KEYCLOAK_BASE_URL}/.well-known/openid-configuration'

# For django-allauth (if using)
SOCIALACCOUNT_PROVIDERS = {
    'keycloak': {
        'KEYCLOAK_URL': KEYCLOAK_SERVER_URL,
        'KEYCLOAK_REALM': KEYCLOAK_REALM,
        'APP': {
            'client_id': KEYCLOAK_CLIENT_ID,
            'secret': KEYCLOAK_CLIENT_SECRET,
        }
    }
}
```

### 6.1 Test Login Flow
1. **Open browser** to: 
   ```
   http://localhost:8080/realms/django-app/protocol/openid-connect/auth?client_id=django-client&response_type=code&redirect_uri=http://localhost:8000/auth/callback/&scope=openid
   ```
2. **You should see** the Keycloak login page
3. **Try logging in** with your test user credentials

### 6.2 Verify Client Configuration
1. **Go back to Admin Console**
2. **Clients → django-client → Settings**
3. **Verify all URLs** are correct
4. **Note down the Client Secret** from Credentials tab

---

## Summary - What You've Created:

✅ **Realm**: `django-app` - Your application's security domain  
✅ **Client**: `django-client` - Your Django application's OAuth2 client  
✅ **User Registration**: Enabled for self-service signup  
✅ **Test User**: Created for testing authentication  
✅ **URLs**: Configured for Django development server  

## Next Steps:

1. **Complete the Keycloak setup** following the steps above
2. **Copy the Client Secret** from the Credentials tab
3. **Test the login flow** using the URL provided
4. **Let me know when ready** to integrate with Django

