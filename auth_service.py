"""
Authentication Service - Multi-provider OAuth handler
Supports GitHub, Google, and extensible to other providers.

Deploy to Railway, Cloud Run, Fly.io, etc.

Environment variables:
- BASE_URL: Your deployment URL (e.g., https://auth.yourdomain.com)
- DATABASE_URL: PostgreSQL connection string
- SECRET_KEY: Session encryption key
- GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
- GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
"""

import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, jsonify
import requests
from functools import wraps
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Configuration
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# OAuth Provider Configurations
PROVIDERS = {
    "github": {
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "user_info_url": "https://api.github.com/user",
        "scope": "user:email",
    },
    "google": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile",
    },
}

# Simple in-memory token store (use Redis/PostgreSQL in production)
TOKEN_STORE = {}


def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        
        api_key = auth_header.split("Bearer ")[1]
        token_data = TOKEN_STORE.get(api_key)
        
        if not token_data:
            return jsonify({"error": "Invalid token"}), 401
        
        # Check expiration
        if token_data.get("expires_at") and datetime.now() > token_data["expires_at"]:
            TOKEN_STORE.pop(api_key, None)
            return jsonify({"error": "Token expired"}), 401
        
        request.token_data = token_data
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def home():
    """Service info and documentation."""
    return jsonify({
        "service": "Authentication Service",
        "version": "1.0.0",
        "providers": list(PROVIDERS.keys()),
        "endpoints": {
            "login": f"{BASE_URL}/auth/<provider>",
            "callback": f"{BASE_URL}/callback/<provider>",
            "token_info": f"{BASE_URL}/api/token/info",
            "refresh": f"{BASE_URL}/api/token/refresh",
            "revoke": f"{BASE_URL}/api/token/revoke",
        }
    })


@app.route("/auth/<provider>")
def auth_provider(provider):
    """Initiate OAuth flow for a provider."""
    if provider not in PROVIDERS:
        return jsonify({"error": f"Provider '{provider}' not supported"}), 400
    
    config = PROVIDERS[provider]
    if not config["client_id"]:
        return jsonify({"error": f"Provider '{provider}' not configured"}), 500
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_provider"] = provider
    
    # Store return URL if provided
    return_url = request.args.get("return_url")
    if return_url:
        session["return_url"] = return_url
    
    # Build authorization URL
    redirect_uri = f"{BASE_URL}/callback/{provider}"
    auth_url = (
        f"{config['authorize_url']}"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={config['scope']}"
        f"&state={state}"
        f"&response_type=code"
    )
    
    return redirect(auth_url)


@app.route("/callback/<provider>")
def callback(provider):
    """Handle OAuth callback."""
    if provider not in PROVIDERS:
        return jsonify({"error": "Invalid provider"}), 400
    
    # Verify state
    state = request.args.get("state")
    if state != session.get("oauth_state"):
        return jsonify({"error": "Invalid state"}), 400
    
    # Check for errors
    error = request.args.get("error")
    if error:
        return jsonify({"error": error}), 400
    
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "No code provided"}), 400
    
    config = PROVIDERS[provider]
    redirect_uri = f"{BASE_URL}/callback/{provider}"
    
    # Exchange code for token
    token_response = requests.post(
        config["token_url"],
        headers={"Accept": "application/json"},
        data={
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
    )
    
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    
    if not access_token:
        return jsonify({"error": "Failed to get access token", "details": token_data}), 400
    
    # Get user info
    user_info = get_user_info(provider, access_token)
    
    # Generate API key for this session
    api_key = secrets.token_urlsafe(32)
    
    # Store token data
    TOKEN_STORE[api_key] = {
        "provider": provider,
        "access_token": access_token,
        "refresh_token": token_data.get("refresh_token"),
        "user_info": user_info,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(days=30),  # Adjust as needed
    }
    
    # Clean up session
    session.pop("oauth_state", None)
    session.pop("oauth_provider", None)
    return_url = session.pop("return_url", None)
    
    # Return token to client
    if return_url:
        # Redirect back to application with token
        return redirect(f"{return_url}?token={api_key}")
    else:
        # Display token
        return f"""
        <html>
            <head>
                <style>
                    body {{ font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 20px; }}
                    .token {{ background: #f5f5f5; padding: 15px; border-radius: 5px; word-break: break-all; }}
                    .success {{ color: #22c55e; }}
                </style>
            </head>
            <body>
                <h1 class="success">✅ Authentication Successful</h1>
                <p>Provider: <strong>{provider}</strong></p>
                <p>User: <strong>{user_info.get('name', user_info.get('login', 'Unknown'))}</strong></p>
                <h3>Your API Token:</h3>
                <div class="token">{api_key}</div>
                <p><small>Save this token securely. Use it in the Authorization header:</small></p>
                <pre>Authorization: Bearer {api_key}</pre>
            </body>
        </html>
        """


def get_user_info(provider, access_token):
    """Fetch user info from provider."""
    config = PROVIDERS[provider]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = requests.get(config["user_info_url"], headers=headers)
    if response.status_code != 200:
        return {"error": "Failed to fetch user info"}
    
    return response.json()


@app.route("/api/token/info", methods=["GET"])
@require_auth
def token_info():
    """Get information about the current token."""
    token_data = request.token_data
    return jsonify({
        "provider": token_data["provider"],
        "user": token_data["user_info"],
        "created_at": token_data["created_at"].isoformat(),
        "expires_at": token_data["expires_at"].isoformat() if token_data.get("expires_at") else None,
    })


@app.route("/api/token/access", methods=["GET"])
@require_auth
def get_access_token():
    """Get the underlying OAuth access token."""
    token_data = request.token_data
    return jsonify({
        "provider": token_data["provider"],
        "access_token": token_data["access_token"],
    })


@app.route("/api/token/refresh", methods=["POST"])
@require_auth
def refresh_token():
    """Refresh the OAuth token if supported."""
    token_data = request.token_data
    refresh_token = token_data.get("refresh_token")
    
    if not refresh_token:
        return jsonify({"error": "No refresh token available"}), 400
    
    provider = token_data["provider"]
    config = PROVIDERS[provider]
    
    # Refresh token (implementation varies by provider)
    # This is a simplified example
    return jsonify({"error": "Refresh not implemented for this provider"}), 501


@app.route("/api/token/revoke", methods=["POST"])
@require_auth
def revoke_token():
    """Revoke the current token."""
    auth_header = request.headers.get("Authorization")
    api_key = auth_header.split("Bearer ")[1]
    
    TOKEN_STORE.pop(api_key, None)
    
    return jsonify({"message": "Token revoked successfully"})


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"})


# CORS support
@app.after_request
def after_request(response):
    origin = request.headers.get("Origin")
    if origin and (CORS_ORIGINS[0] == "*" or origin in CORS_ORIGINS):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


if __name__ == "__main__":
    # Validate configuration
    configured_providers = [p for p, c in PROVIDERS.items() if c["client_id"]]
    
    if not configured_providers:
        print("⚠️  Warning: No OAuth providers configured!")
        print("Set environment variables for at least one provider:")
        for provider in PROVIDERS:
            print(f"  - {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET")
    
    print(f"🚀 Auth Service starting...")
    print(f"📍 Base URL: {BASE_URL}")
    print(f"🔐 Configured providers: {', '.join(configured_providers) or 'none'}")
    
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("ENV") != "production")
