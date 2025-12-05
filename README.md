# Agentbase

## Overview
This guide covers deploying the Streamlit Agentbase application to Google Cloud Run with Identity-Aware Proxy (IAP) authentication, integrated with Entra ID.

---

## Prerequisites

1. **Google Cloud Project** with billing enabled
2. **APIs enabled:**
   ```bash
   gcloud services enable \
     run.googleapis.com \
     iap.googleapis.com \
     aiplatform.googleapis.com \
     compute.googleapis.com
   ```
3. **Entra ID tenant** with admin access
4. **gcloud CLI** installed and authenticated

---

## Step 1: Prepare Service Account

Create a service account for Cloud Run with necessary permissions:

```bash
PROJECT_ID="your-project-id"
SERVICE_ACCOUNT_NAME="agentbase-runner"

# Create service account
gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} \
    --display-name="Agentbase Cloud Run Service Account" \
    --project=${PROJECT_ID}

# Grant Vertex AI permissions
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

# Grant logging permissions
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/logging.logWriter"
```

---

## Step 2: Build and Deploy to Cloud Run

### Option A: Deploy from Source

```bash
# Set variables
REGION="us-central1"
SERVICE_NAME="agentbase"

# Deploy
gcloud run deploy ${SERVICE_NAME} \
    --source . \
    --platform managed \
    --region ${REGION} \
    --service-account ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --no-allow-unauthenticated \
    --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION}" \
    --max-instances 10 \
    --memory 2Gi \
    --timeout 300 \
    --project ${PROJECT_ID}
```

### Option B: Deploy from Container

```bash
# Build container
gcloud builds submit --tag gcr.io/${PROJECT_ID}/${SERVICE_NAME}

# Deploy
gcloud run deploy ${SERVICE_NAME} \
    --image gcr.io/${PROJECT_ID}/${SERVICE_NAME} \
    --platform managed \
    --region ${REGION} \
    --service-account ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --no-allow-unauthenticated \
    --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION}" \
    --max-instances 10 \
    --memory 2Gi \
    --timeout 300 \
    --project ${PROJECT_ID}
```

---

## Step 3: Configure Entra ID as External Identity Provider

### 3.1 Create Entra ID App Registration

1. Go to **Azure Portal** > **Microsoft Entra ID** > **App registrations**
2. Click **New registration**
   - Name: `Agentbase IAP`
   - Supported account types: Choose appropriate option
   - Redirect URI: Leave blank (will add later)
3. Note the **Application (client) ID** and **Directory (tenant) ID**

### 3.2 Create Client Secret

1. In your app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Note the **secret value** (you can only see it once)

### 3.3 Configure Redirect URIs

After IAP is set up, add this redirect URI in Entra ID:
```
https://iap.googleapis.com/v1/oauth/clientIds/YOUR_IAP_CLIENT_ID:handleRedirect
```

---

## Step 4: Enable IAP for Cloud Run (One-Click Method)

### 4.1 Enable IAP via Cloud Console

1. Go to **Cloud Console** > **Cloud Run** > Select your service
2. Click **Security** tab
3. Under **Authentication**, click **Enable IAP**
4. Configure external identity provider:
   - Choose **External identities**
   - Select **OIDC** as provider type
   - Configure Entra ID:
     - **Issuer URL**: `https://login.microsoftonline.com/{TENANT_ID}/v2.0`
     - **Client ID**: From Entra ID app registration
     - **Client Secret**: From Entra ID app registration
5. Click **Save**

### 4.2 Get IAP Audience for Cloud Run

For the new Cloud Run IAP, the audience format is different from traditional IAP:

**Method 1: From Cloud Run Service Details**
```bash
gcloud run services describe SERVICE_NAME \
    --region=REGION \
    --format="value(metadata.annotations.'run.googleapis.com/iap-jwt-audience')"
```

**Method 2: From JWT Token (after first login)**
After you first access the service, check the JWT token. The `aud` claim will show the audience.

**Method 3: Use Project-based Audience**
For Cloud Run with IAP, the audience is typically:
```
/projects/PROJECT_NUMBER/apps/PROJECT_ID
```

To get your PROJECT_NUMBER:
```bash
gcloud projects describe PROJECT_ID --format="value(projectNumber)"
```

Then construct:
```bash
IAP_AUDIENCE="/projects/$(gcloud projects describe PROJECT_ID --format='value(projectNumber)')/apps/PROJECT_ID"

echo $IAP_AUDIENCE
# Output: /projects/123456789/apps/your-project-id
```

### 4.3 Update Cloud Run with IAP Audience

Grant access to specific users/groups:

```bash
# For individual users
gcloud iap web add-iam-policy-binding \
    --resource-type=backend-services \
    --service=${SERVICE_NAME} \
    --region=${REGION} \
    --member="user:someone@example.com" \
    --role="roles/iap.httpsResourceAccessor" \
    --project=${PROJECT_ID}

# For groups (requires Cloud Identity or Workspace)
gcloud iap web add-iam-policy-binding \
    --resource-type=backend-services \
    --service=${SERVICE_NAME} \
    --region=${REGION} \
    --member="group:team@example.com" \
    --role="roles/iap.httpsResourceAccessor" \
    --project=${PROJECT_ID}
```

---

## Step 6: Update Application Configuration

Update your Cloud Run service with the IAP audience:

```bash
gcloud run services update ${SERVICE_NAME} \
    --region ${REGION} \
    --set-env-vars "IAP_AUDIENCE=/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID" \
    --project ${PROJECT_ID}
```

---

## Step 7: Verify Deployment

1. Get your Cloud Run URL:
   ```bash
   gcloud run services describe ${SERVICE_NAME} \
       --region ${REGION} \
       --format "value(status.url)" \
       --project ${PROJECT_ID}
   ```

2. Visit the URL in a browser
3. You should be redirected to Entra ID for authentication
4. After authentication, you should see the Streamlit app with your email displayed

---

## Authentication Flow

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌──────────────┐
│  User   │────▶│Entra ID │────▶│   IAP    │────▶│  Cloud Run   │
│ Browser │     │  (Auth) │     │(Validate)│     │  (Streamlit) │
└─────────┘     └─────────┘     └──────────┘     └──────────────┘
                                      │
                                      ▼
                               Inject JWT Header
                         X-Goog-IAP-JWT-Assertion
                                      │
                                      ▼
                              ┌───────────────┐
                              │  Streamlit    │
                              │  Reads header │
                              │  via internal │
                              │  websocket    │
                              │  API          │
                              └───────────────┘
                                      │
                                      ▼
                              ┌───────────────┐
                              │  Validate JWT │
                              │  Extract      │
                              │  User Email   │
                              └───────────────┘
                                      │
                                      ▼
                              ┌───────────────┐
                              │  Vertex AI    │
                              │  Agent Engine │
                              │  (user_id =   │
                              │   email)      │
                              └───────────────┘
```

**Important:** Streamlit doesn't expose HTTP headers in the standard API. The app uses `streamlit.web.server.websocket_headers._get_websocket_headers()` to access the IAP JWT. This is an internal API, but it's the only way to read headers in Streamlit.

---

## Troubleshooting

### Issue: Don't know the IAP Audience

**Problem:** Can't find the correct audience format for JWT validation

**Solution - Skip validation temporarily:**
```python
# In streamlit_app.py, modify get_authenticated_user()
def get_authenticated_user():
    if os.getenv("ENVIRONMENT") == "development":
        return os.getenv("DEV_USER_EMAIL", "dev@example.com")
    
    try:
        headers = st.context.headers
        if headers is None:
            return None
        
        iap_jwt = headers.get("X-Goog-Iap-Jwt-Assertion")
        if not iap_jwt:
            return None
        
        # TEMPORARY: Decode without verification to see the audience
        import jwt
        decoded = jwt.decode(iap_jwt, options={"verify_signature": False})
        st.sidebar.info(f"JWT Audience: {decoded.get('aud')}")
        
        # Extract email without validation (for testing only)
        return decoded.get("email")
        
    except Exception as e:
        st.error(f"Error: {e}")
        return None
```

Then use the displayed audience value in your `IAP_AUDIENCE` environment variable.

### Issue: JWT Validation Fails

**Problem:** User cannot access app after authentication

**Solutions:**
1. Verify `IAP_AUDIENCE` environment variable is set correctly
2. Check Cloud Run logs: `gcloud run services logs read ${SERVICE_NAME}`
3. Ensure service account has necessary permissions
4. Verify headers are being received: Add debug logging in `get_authenticated_user()`

### Issue: Headers Not Available

**Problem:** `_get_websocket_headers()` returns None

**Solutions:**
1. This is a known Streamlit limitation - headers may not be available in all contexts
2. Verify you're accessing the app via HTTPS (required for IAP)
3. Check Streamlit version compatibility (tested with 1.51.0)
4. Alternative: Use a lightweight ASGI middleware wrapper (see below for advanced solution)

**Advanced Alternative:** If `_get_websocket_headers()` is unreliable, you can wrap Streamlit in a lightweight ASGI app that extracts headers and passes them via query params or session state. This is more complex but more robust.

### Issue: Cannot List Agents

**Problem:** "No agents found" message in sidebar

**Solutions:**
1. Verify service account has `roles/aiplatform.user`
2. Check that agents exist in the specified project/location
3. Verify `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` are set

### Issue: Session Isolation Not Working

**Problem:** Users seeing each other's conversations

**Solutions:**
1. Verify JWT is being extracted correctly (check logs)
2. Ensure `user_email` is being passed to agent calls
3. Check session state isolation in code

---

## Local Development (Without IAP)

For local testing without IAP:

```bash
# Set environment variables
export ENVIRONMENT="development"
export DEV_USER_EMAIL="your-email@example.com"
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="us-central1"

# Run Streamlit
streamlit run streamlit_app.py
```

---

## Security Best Practices

1. **Least Privilege:** Only grant IAP access to necessary users/groups
2. **Audit Logging:** Enable Cloud Audit Logs for IAP access
3. **Service Account:** Use dedicated service account with minimal permissions
4. **Session Timeout:** Configure appropriate session timeout in IAP settings
5. **HTTPS Only:** Cloud Run enforces HTTPS by default
6. **Environment Variables:** Never commit credentials; use Secret Manager for sensitive values

---

## Cost Considerations (Prototype)

- **Cloud Run:** Pay per request, scales to zero
- **IAP:** No additional cost
- **Vertex AI Agent Engine:** Based on usage
- **Estimated monthly cost** (light usage): $10-50

---

## Next Steps

1. Set up monitoring and alerting
2. Configure custom domain
3. Implement rate limiting
4. Add audit logging for agent interactions
5. Consider Cloud Armor for DDoS protection (production)
