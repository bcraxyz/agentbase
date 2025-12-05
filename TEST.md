# Test Strategy

## Overview
The `test.py` file demonstrates direct REST API interaction with Vertex AI Discovery Engine agents. This document outlines how to integrate it into the Streamlit app to showcase authentication and authorization flows.

---

## Key Differences: SDK vs REST API

| Aspect | SDK (Current) | REST API (test.py) |
|--------|---------------|-------------------|
| **Abstraction** | High-level, simple | Low-level, granular |
| **Authentication** | Automatic via ADC | Manual with `AuthorizedSession` |
| **Session Mgmt** | Built-in | Manual tracking |
| **Parameters** | Limited, simplified | Full control, advanced options |
| **Error Handling** | SDK exceptions | HTTP status codes + JSON |
| **API Stability** | GA (stable) | v1alpha (experimental) |

---

## Authentication Flow Comparison

### SDK Approach (Current Implementation)
```
IAP JWT → Parse User Email → Pass to SDK
                                ↓
                        Vertex AI SDK
                                ↓
                        ADC Credentials
                                ↓
                        API Call with user_id
```

### REST API Approach (test.py)
```
IAP JWT → Parse User Email → Build Request Body
                                ↓
                        google.auth.default()
                                ↓
                        AuthorizedSession
                                ↓
                        Direct API Call with userMetadata
```

**Key Insight:** Both use the **same underlying authentication** (Application Default Credentials from the Cloud Run service account). The user identity from IAP is just metadata passed in the request.

---

## Recommended Integration: Demo Mode

Add a "Demo Mode" to showcase both approaches side-by-side:

### Implementation Plan

1. **Add Toggle in Sidebar:**
   ```python
   st.sidebar.subheader("🔬 Demo Mode")
   api_mode = st.sidebar.radio(
       "API Interaction Style",
       ["SDK (Recommended)", "REST API (Advanced)", "Side-by-Side Comparison"]
   )
   ```

2. **Create Separate Functions:**
   - `chat_with_agent_sdk()` - Current implementation
   - `chat_with_agent_rest()` - Based on test.py
   - `chat_with_agent_comparison()` - Shows both

3. **Display Auth Flow Diagram:**
   Show a visual representation of how authentication flows through each approach

---

## Why This Matters for Auth/Authz Demo

### Authentication Aspects

1. **IAP Layer:**
   - User authenticates via Entra ID
   - IAP validates and injects JWT
   - Both SDK and REST API receive the same validated user identity

2. **GCP Service Account:**
   - Cloud Run service account has permissions to call Vertex AI
   - This is the **authorization** layer
   - User identity is metadata, not the auth principal

3. **Vertex AI Agent Engine:**
   - Receives requests from authorized service account
   - Uses `user_id` for session isolation
   - Logs activity per user for audit

### Authorization Chain

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: IAP Authentication (Entra ID)                  │
│ → Validates: Who is the user?                           │
│ → Output: JWT with user email                           │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Cloud Run Authorization (IAM)                  │
│ → Validates: Can this user access the service?          │
│ → Check: roles/iap.httpsResourceAccessor                │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Vertex AI Authorization (Service Account IAM)  │
│ → Validates: Can the service account call Vertex AI?    │
│ → Check: roles/aiplatform.user                          │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Agent Engine (User Isolation)                  │
│ → Uses: user_id from IAP for session isolation          │
│ → Audit: All queries logged with user identity          │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation: REST API Chat Function

Here's how to adapt test.py for Streamlit with IAP:

```python
import json
import google.auth
from google.auth.transport.requests import AuthorizedSession

def chat_with_agent_rest(
    project_id: str,
    location: str,
    engine_id: str,
    agent_id: str,
    message: str,
    user_email: str,
    session_id: str = None
):
    """
    Chat with agent using REST API (demonstrating low-level interaction).
    Shows how authentication flows through direct API calls.
    """
    # Select API endpoint based on location
    api_base = (
        "discoveryengine.googleapis.com" 
        if location == "global" 
        else f"{location}-discoveryengine.googleapis.com"
    )
    
    assistant_name = (
        f"projects/{project_id}/locations/{location}/"
        f"collections/default_collection/engines/{engine_id}/"
        f"assistants/default_assistant"
    )
    
    api_endpoint = (
        f"https://{api_base}/v1alpha/{assistant_name}:streamAssist"
    )
    
    # Get credentials (same as SDK, but explicit)
    credentials, _ = google.auth.default()
    authed_session = AuthorizedSession(credentials)
    
    # Build request body
    request_body = {
        "query": {"text": message},
        "answerGenerationMode": "AGENT",
        "agentsSpec": {
            "agentSpecs": [
                {"agentId": agent_id}
            ]
        },
        "userMetadata": {
            "userId": user_email,  # User from IAP JWT
            "timeZone": "UTC"
        }
    }
    
    # Add session if exists
    if session_id:
        request_body["sessionId"] = session_id
    
    # Make API call
    response = authed_session.post(
        api_endpoint,
        headers={"Content-Type": "application/json"},
        data=json.dumps(request_body)
    )
    
    # Parse streaming response
    output = ''
    try:
        data_array = json.loads(response.text)
        for data in data_array:
            if data.get('answer', {}).get('state') == 'IN_PROGRESS':
                content = data['answer']['replies'][-1]['groundedContent'].get('content', {})
                if not content.get('thought', False):
                    streaming_response = content.get('text', '')
                    if streaming_response:
                        output += streaming_response
        
        # Extract session ID from response if new session
        new_session_id = None
        if data_array and 'session' in data_array[-1]:
            new_session_id = data_array[-1]['session']['name']
        
        return output, new_session_id
    except Exception as e:
        raise Exception(f"REST API Error: {str(e)}\nResponse: {response.text}")
```

---

## What This Demonstrates

### For Authentication Flow:
1. **User Identity Propagation:**
   - User logs in via Entra ID → IAP
   - Email extracted from JWT
   - Passed through to agent as `user_id` / `userMetadata.userId`
   - Same identity in both SDK and REST approaches

2. **Service Account Authorization:**
   - Both SDK and REST use ADC
   - Cloud Run service account must have `roles/aiplatform.user`
   - User's Entra ID identity doesn't need GCP IAM roles

3. **Audit Trail:**
   - All agent queries logged with user email
   - Can trace who asked what
   - Session isolation per user

### For Authorization Flow:
1. **Layered Security:**
   - IAP: Who can access the app?
   - IAM: What can the service account do?
   - Agent Engine: Per-user session isolation

2. **Separation of Concerns:**
   - User authentication (Entra ID + IAP)
   - Service authorization (GCP IAM)
   - Resource access (Vertex AI permissions)

---

## Recommendation

**For your prototype, implement Option 3 (Side-by-Side Comparison):**

Benefits:
- Clearly demonstrates authentication flow in both approaches
- Shows that auth is handled consistently regardless of API style
- Educational value for understanding the abstraction layers
- Minimal additional code (reuse test.py logic)

Implementation:
1. Add REST API function to streamlit_app.py
2. Add radio button to switch modes
3. Optionally show both responses side-by-side
4. Add visual diagram of auth flow in an expander

This gives you a complete demo showing:
- How IAP authentication works
- How service account authorization works  
- How user identity propagates through different API layers
- The value of SDK abstraction vs. REST API control
