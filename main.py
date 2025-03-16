import os
import secrets
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import tweepy
import json
import ssl
import socket
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Twitter API credentials
# OAuth2 credentials
TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
TWITTER_CALLBACK_URL = os.getenv("TWITTER_CALLBACK_URL", "https://mydomain.com:8000/callback")

# OAuth1 credentials
TWITTER_CONSUMER_KEY = os.getenv("TWITTER_CONSUMER_KEY")
TWITTER_CONSUMER_SECRET = os.getenv("TWITTER_CONSUMER_SECRET")

# Function to generate self-signed certificates
def generate_self_signed_cert(cert_file="localhost.crt", key_file="localhost.key"):
    """Generate a self-signed certificate for localhost"""
    # Check if certificate files already exist
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Certificate files {cert_file} and {key_file} already exist. Using existing files.")
        return cert_file, key_file
    
    print("Generating self-signed certificate for localhost...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Twitter Auth Sandbox"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mydomain.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write the certificate and private key to disk
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Self-signed certificate generated: {cert_file}, {key_file}")
    return cert_file, key_file

# Custom middleware for Content Security Policy
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://accounts.google.com https://www.gstatic.com https://*.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https://*.googleusercontent.com https://*.google.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' https://*.googleapis.com https://accounts.google.com; "
            "frame-src 'self' https://accounts.google.com; "
            "frame-ancestors 'self' *.twitter.com;"
        )
        # Add Cross-Origin-Opener-Policy header to allow window.opener communication
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        return response

# FastAPI app setup
app = FastAPI(title="Twitter Auth Sandbox")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)))
app.add_middleware(CSPMiddleware)  # Add CSP middleware

# Setup templates
templates = Jinja2Templates(directory="templates")

# Create templates directory if it doesn't exist
os.makedirs("templates", exist_ok=True)

# Create static directory if it doesn't exist
os.makedirs("static", exist_ok=True)

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create shared OAuth2 handler
oauth2_user_handler = tweepy.OAuth2UserHandler(
    client_id=TWITTER_CLIENT_ID,
    client_secret=TWITTER_CLIENT_SECRET,
    redirect_uri=TWITTER_CALLBACK_URL,
    scope=["tweet.read", "users.read"],
)

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page with authentication options"""
    return templates.TemplateResponse("index.html", {"request": request})

# OAuth2 Routes
@app.get("/oauth2-login")
async def oauth2_login(request: Request):
    """Standard OAuth2 Twitter login flow"""

    # Store that we're doing OAuth2
    request.session["auth_flow"] = "oauth2"
    
    # Get the authorization URL
    auth_url = oauth2_user_handler.get_authorization_url()
    
    return RedirectResponse(auth_url)

@app.get("/oauth2-silent-check")
async def oauth2_silent_check(request: Request):
    """Silent OAuth2 check to verify if user is already authenticated"""
    request.session["auth_flow"] = "oauth2"
    request.session["silent_check"] = True
    
    # Get the authorization URL
    auth_url = oauth2_user_handler.get_authorization_url()
    
    return RedirectResponse(auth_url)

# OAuth1 Routes
@app.get("/oauth1-login")
async def oauth1_login(request: Request):
    """Standard OAuth1 Twitter login flow"""
    try:
        # Create OAuth1 handler
        oauth1_handler = tweepy.OAuthHandler(
            consumer_key=TWITTER_CONSUMER_KEY,
            consumer_secret=TWITTER_CONSUMER_SECRET,
            callback=TWITTER_CALLBACK_URL
        )
        
        # Get request token and store in session
        redirect_url = oauth1_handler.get_authorization_url()
        request.session["oauth1_request_token"] = oauth1_handler.request_token
        request.session["auth_flow"] = "oauth1"
        request.session["auth_variant"] = "authorize"
        
        return RedirectResponse(redirect_url)
    except Exception as e:
        print(f"OAuth1 Error: {e}")
        return {"error": str(e)}

@app.get("/oauth1-signin")
async def oauth1_signin(request: Request):
    """OAuth1 Twitter login flow using authenticate endpoint (Sign in with Twitter)"""
    try:
        # Create OAuth1 handler
        oauth1_handler = tweepy.OAuthHandler(
            consumer_key=TWITTER_CONSUMER_KEY,
            consumer_secret=TWITTER_CONSUMER_SECRET,
            callback=TWITTER_CALLBACK_URL
        )
        
        # Get request token with signin_with_twitter=True and store in session
        redirect_url = oauth1_handler.get_authorization_url(signin_with_twitter=True)
        request.session["oauth1_request_token"] = oauth1_handler.request_token
        request.session["auth_flow"] = "oauth1"
        request.session["auth_variant"] = "authenticate"
        
        return RedirectResponse(redirect_url)
    except Exception as e:
        print(f"OAuth1 Signin Error: {e}")
        return {"error": str(e)}

@app.get("/oauth1-silent-check")
async def oauth1_silent_check(request: Request):
    """Silent OAuth1 check to verify if user is already authenticated"""
    try:
        # Create OAuth1 handler
        oauth1_handler = tweepy.OAuthHandler(
            consumer_key=TWITTER_CONSUMER_KEY,
            consumer_secret=TWITTER_CONSUMER_SECRET,
            callback=TWITTER_CALLBACK_URL
        )
        
        # Get request token and store in session
        redirect_url = oauth1_handler.get_authorization_url()
        request.session["oauth1_request_token"] = oauth1_handler.request_token
        request.session["auth_flow"] = "oauth1"
        request.session["auth_variant"] = "authorize"
        request.session["silent_check"] = True
        
        return RedirectResponse(redirect_url)
    except Exception as e:
        print(f"OAuth1 Silent Check Error: {e}")
        return HTMLResponse(f"""
            <script>
                window.parent.postMessage(
                    {{ type: 'twitter-auth-result', 
                       flow: 'oauth1',
                       variant: 'authorize',
                       success: false, 
                       reason: 'request_token_failed',
                       error: '{str(e)}' }}, 
                    '*'
                );
            </script>
        """)

@app.get("/oauth1-signin-silent-check")
async def oauth1_signin_silent_check(request: Request):
    """Silent OAuth1 check using authenticate endpoint (Sign in with Twitter)"""
    try:
        # Create OAuth1 handler
        oauth1_handler = tweepy.OAuthHandler(
            consumer_key=TWITTER_CONSUMER_KEY,
            consumer_secret=TWITTER_CONSUMER_SECRET,
            callback=TWITTER_CALLBACK_URL
        )
        
        # Get request token with signin_with_twitter=True and store in session
        redirect_url = oauth1_handler.get_authorization_url(signin_with_twitter=True)
        request.session["oauth1_request_token"] = oauth1_handler.request_token
        request.session["auth_flow"] = "oauth1"
        request.session["auth_variant"] = "authenticate"
        request.session["silent_check"] = True
        
        return RedirectResponse(redirect_url)
    except Exception as e:
        print(f"OAuth1 Signin Silent Check Error: {e}")
        return HTMLResponse(f"""
            <script>
                window.parent.postMessage(
                    {{ type: 'twitter-auth-result', 
                       flow: 'oauth1',
                       variant: 'authenticate',
                       success: false, 
                       reason: 'request_token_failed',
                       error: '{str(e)}' }}, 
                    '*'
                );
            </script>
        """)

# Unified callback handler
@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None, 
                   oauth_token: str = None, oauth_verifier: str = None, 
                   denied: str = None, error: str = None):
    """Unified callback handler for both OAuth1 and OAuth2"""
    
    # Determine which auth flow we're handling
    auth_flow = request.session.get("auth_flow")
    is_silent = request.session.get("silent_check", False)
    
    # Handle OAuth2 flow
    if auth_flow == "oauth2":
        # Check for errors
        if error:
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {error}</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth2',
                                   success: false, 
                                   reason: '{error}' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth2',
                                    success: false,
                                    reason: '{error}'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
        
        # If no code, the user denied access or needs to log in
        if not code:
            return HTMLResponse("""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Authorization denied or no code provided.</p>
                    <script>
                        if (window.parent !== window) {
                            // For iframe (silent check)
                            window.parent.postMessage(
                                { type: 'twitter-auth-result', 
                                  flow: 'oauth2',
                                  success: false, 
                                  reason: 'authorization_denied' }, 
                                '*'
                            );
                        } else if (window.opener) {
                            // For popup window
                            window.opener.postMessage(
                                { 
                                    type: 'auth-complete',
                                    flow: 'oauth2',
                                    success: false,
                                    reason: 'authorization_denied'
                                }, 
                                window.location.origin
                            );
                        }
                    </script>
                </body>
                </html>
            """)
        
        try:
            # Get access tokenp
            print(f"OAuth2 callback received with code: {code[:10]}...")  # Only print first 10 chars for security
            # Construct the full authorization URL with the code parameter
            authorization_response = f"{TWITTER_CALLBACK_URL}?code={code}"
            if state:
                authorization_response += f"&state={state}"
            access_token = oauth2_user_handler.fetch_token(authorization_response)

            # Create client
            print("client", access_token)
            client = tweepy.Client(access_token["access_token"])
            
            user_data = client.get_me(user_fields=["profile_image_url", "description", "name"], user_auth=False)
            
            # Store token in session
            request.session["oauth2_token"] = access_token
            request.session["twitter_user_id"] = user_data.data.id
            request.session["auth_method"] = "oauth2"
            
            # Clear temporary session data
            if "auth_flow" in request.session:
                del request.session["auth_flow"]
            if "silent_check" in request.session:
                del request.session["silent_check"]
            
            # Return success message or redirect based on if it's a silent check
            if is_silent:
                return HTMLResponse(f"""
                    <script>
                        window.parent.postMessage(
                            {{ 
                                type: 'twitter-auth-result', 
                                flow: 'oauth2',
                                success: true, 
                                userData: {{
                                    id: '{user_data.data.id}',
                                    username: '{user_data.data.username}',
                                    name: '{user_data.data.name}',
                                    description: '{user_data.data.description if user_data.data.description else ""}',
                                    profile_image: '{user_data.data.profile_image_url if user_data.data.profile_image_url else ""}'
                                }}
                            }}, 
                            '*'
                        );
                    </script>
                """)
            else:
                # For popup window authentication, send message to opener and close window
                return HTMLResponse(f"""
                    <html>
                    <head>
                        <title>Authentication Complete</title>
                    </head>
                    <body>
                        <h1>Authentication Complete</h1>
                        <p>You have successfully authenticated with Twitter. This window will close automatically.</p>
                        <script>
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth2',
                                    success: true
                                }}, 
                                window.location.origin
                            );
                            // Close this popup window after sending the message
                            setTimeout(function() {{
                                window.close();
                                // If window doesn't close (e.g., if it wasn't opened by JavaScript)
                                if (window.opener) {{
                                    window.location.href = "/";
                                }}
                            }}, 1000);
                        </script>
                    </body>
                    </html>
                """)
                
        except Exception as e:
            print(f"OAuth2 Error: {e}")
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {str(e)}</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth2',
                                   success: false, 
                                   reason: 'token_exchange_failed', 
                                   error: '{str(e)}' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth2',
                                    success: false,
                                    reason: 'token_exchange_failed',
                                    error: '{str(e)}'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
    
    # Handle OAuth1 flow
    elif auth_flow == "oauth1":
        # Get the auth variant (authorize or authenticate)
        auth_variant = request.session.get("auth_variant", "authorize")
        
        # Check if access was denied
        if denied:
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Access was denied.</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth1',
                                   variant: '{auth_variant}',
                                   success: false, 
                                   reason: 'authorization_denied' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth1',
                                    variant: '{auth_variant}',
                                    success: false,
                                    reason: 'authorization_denied'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
        
        # Check for required parameters
        if not oauth_token or not oauth_verifier:
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Missing required parameters.</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth1',
                                   variant: '{auth_variant}',
                                   success: false, 
                                   reason: 'missing_parameters' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth1',
                                    variant: '{auth_variant}',
                                    success: false,
                                    reason: 'missing_parameters'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
        
        # Get stored request token
        request_token = request.session.get("oauth1_request_token")
        if not request_token:
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Missing request token.</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth1',
                                   variant: '{auth_variant}',
                                   success: false, 
                                   reason: 'missing_request_token' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth1',
                                    variant: '{auth_variant}',
                                    success: false,
                                    reason: 'missing_request_token'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
        
        try:
            # Create OAuth handler
            oauth1_handler = tweepy.OAuthHandler(
                consumer_key=TWITTER_CONSUMER_KEY,
                consumer_secret=TWITTER_CONSUMER_SECRET
            )
            
            # Set request token
            oauth1_handler.request_token = request_token
            
            # Get access token
            oauth1_handler.get_access_token(oauth_verifier)
            
            # Create API client
            api = tweepy.API(oauth1_handler)
            
            # Get user info
            user = api.verify_credentials(include_email=True)
            
            # Store tokens in session
            request.session["oauth1_access_token"] = oauth1_handler.access_token
            request.session["oauth1_access_token_secret"] = oauth1_handler.access_token_secret
            request.session["twitter_user_id"] = user.id
            request.session["auth_method"] = "oauth1"
            request.session["auth_variant"] = auth_variant
            
            # Clear temporary session data
            if "oauth1_request_token" in request.session:
                del request.session["oauth1_request_token"]
            if "auth_flow" in request.session:
                del request.session["auth_flow"]
            if "silent_check" in request.session:
                del request.session["silent_check"]
            
            # Return success message or redirect based on if it's a silent check
            if is_silent:
                return HTMLResponse(f"""
                    <script>
                        window.parent.postMessage(
                            {{ 
                                type: 'twitter-auth-result', 
                                flow: 'oauth1',
                                variant: '{auth_variant}',
                                success: true, 
                                userData: {{
                                    id: '{user.id}',
                                    username: '{user.screen_name}',
                                    name: '{user.name}',
                                    description: '{user.description if user.description else ""}',
                                    profile_image: '{user.profile_image_url if hasattr(user, "profile_image_url") else ""}'
                                }}
                            }}, 
                            '*'
                        );
                    </script>
                """)
            else:
                # For popup window authentication, send message to opener and close window
                return HTMLResponse(f"""
                    <html>
                    <head>
                        <title>Authentication Complete</title>
                    </head>
                    <body>
                        <h1>Authentication Complete</h1>
                        <p>You have successfully authenticated with Twitter. This window will close automatically.</p>
                        <script>
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth1',
                                    variant: '{auth_variant}',
                                    success: true
                                }}, 
                                window.location.origin
                            );
                            // Close this popup window after sending the message
                            setTimeout(function() {{
                                window.close();
                                // If window doesn't close (e.g., if it wasn't opened by JavaScript)
                                if (window.opener) {{
                                    window.location.href = "/";
                                }}
                            }}, 1000);
                        </script>
                    </body>
                    </html>
                """)
                
        except Exception as e:
            print(f"OAuth1 Error: {e}")
            return HTMLResponse(f"""
                <html>
                <head>
                    <title>Authentication Failed</title>
                </head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {str(e)}</p>
                    <script>
                        if (window.parent !== window) {{
                            // For iframe (silent check)
                            window.parent.postMessage(
                                {{ type: 'twitter-auth-result', 
                                   flow: 'oauth1',
                                   variant: '{auth_variant}',
                                   success: false, 
                                   reason: 'token_exchange_failed',
                                   error: '{str(e)}' }}, 
                                '*'
                            );
                        }} else if (window.opener) {{
                            // For popup window
                            window.opener.postMessage(
                                {{ 
                                    type: 'auth-complete',
                                    flow: 'oauth1',
                                    variant: '{auth_variant}',
                                    success: false,
                                    reason: 'token_exchange_failed',
                                    error: '{str(e)}'
                                }}, 
                                window.location.origin
                            );
                        }}
                    </script>
                </body>
                </html>
            """)
    
    # Unknown auth flow
    else:
        return HTMLResponse("""
            <script>
                window.parent.postMessage(
                    { type: 'twitter-auth-result', 
                      success: false, 
                      reason: 'unknown_auth_flow' }, 
                    '*'
                );
            </script>
        """)

@app.get("/user-info")
async def user_info(request: Request):
    """API endpoint to get user information"""
    auth_method = request.session.get("auth_method")
    
    if not auth_method:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        if auth_method == "oauth2":
            token = request.session.get("oauth2_token")
            if not token:
                raise HTTPException(status_code=401, detail="OAuth2 token not found")
                
            client = tweepy.Client(token["access_token"])
            user_data = client.get_me(user_fields=["profile_image_url", "description", "name"], user_auth=False)
            
            return {
                "auth_method": "oauth2",
                "id": user_data.data.id,
                "username": user_data.data.username,
                "name": user_data.data.name,
                "description": user_data.data.description,
                "profile_image": user_data.data.profile_image_url
            }
        
        elif auth_method == "oauth1":
            access_token = request.session.get("oauth1_access_token")
            access_token_secret = request.session.get("oauth1_access_token_secret")
            auth_variant = request.session.get("auth_variant", "authorize")
            
            if not access_token or not access_token_secret:
                raise HTTPException(status_code=401, detail="OAuth1 tokens not found")
            
            auth = tweepy.OAuthHandler(TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET)
            auth.set_access_token(access_token, access_token_secret)
            
            api = tweepy.API(auth)
            user = api.verify_credentials()
            
            return {
                "auth_method": "oauth1",
                "auth_variant": auth_variant,
                "id": user.id,
                "username": user.screen_name,
                "name": user.name,
                "description": user.description,
                "profile_image": user.profile_image_url if hasattr(user, "profile_image_url") else None
            }
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown auth method: {auth_method}")
    
    except Exception as e:
        print(f"User Info Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logout")
async def logout(request: Request):
    """Clear session data to log out"""
    request.session.clear()
    return RedirectResponse(url="/")

if __name__ == "__main__":
    # Create .env file if it doesn't exist
    if not os.path.exists(".env"):
        with open(".env", "w") as f:
            f.write("""# Twitter API credentials
# OAuth2 Credentials
TWITTER_CLIENT_ID=your_client_id_here
TWITTER_CLIENT_SECRET=your_client_secret_here
TWITTER_CALLBACK_URL=https://localhost:8000/callback

# OAuth1 Credentials
TWITTER_CONSUMER_KEY=your_consumer_key_here
TWITTER_CONSUMER_SECRET=your_consumer_secret_here

# Session Security
SESSION_SECRET=generate_a_random_secret_here
""")
        print("Created .env file. Please fill in your Twitter API credentials.")
    
    # Generate self-signed certificates
    cert_file, key_file = generate_self_signed_cert()
    
    # Run the server with the self-signed certificates
    uvicorn.run(app, host="127.0.0.1", port=8000, 
                ssl_keyfile=key_file, 
                ssl_certfile=cert_file)
