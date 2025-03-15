from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import os
import httpx
import json
from dotenv import load_dotenv
from pathlib import Path
import uvicorn

# Load environment variables
load_dotenv()

# Get Google client ID from environment variables
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
if not GOOGLE_CLIENT_ID:
    print("Warning: GOOGLE_CLIENT_ID not found in .env file")

# Create FastAPI app
app = FastAPI(title="Google Auth Playground")

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "supersecretkey")
)

# Set up templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create templates directory if it doesn't exist
Path("templates").mkdir(exist_ok=True)
Path("static").mkdir(exist_ok=True)

# Routes
@app.get("/", response_class=HTMLResponse)
async def google_auth_page(request: Request):
    """Render the Google Auth Playground page"""
    return templates.TemplateResponse(
        "google_auth.html", 
        {"request": request}
    )

@app.get("/api/client-config")
async def get_client_config():
    """Get client configuration for JavaScript initialization"""
    return {"client_id": GOOGLE_CLIENT_ID or ""}

@app.get("/auth/google", response_class=RedirectResponse)
async def google_auth():
    """Redirect to Google OAuth authorization URL"""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google Client ID not configured"
        )
    
    # Create the Google OAuth URL
    redirect_uri = "http://localhost:8000/auth/google/callback"
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        f"&redirect_uri={redirect_uri}"
        "&access_type=online"
    )
    
    return RedirectResponse(auth_url)

@app.get("/auth/google/callback")
async def google_auth_callback(request: Request, code: str = None, error: str = None):
    """Handle the callback from Google OAuth"""
    if error:
        return RedirectResponse(f"/?error={error}")
    
    if not code:
        return RedirectResponse("/?error=no_code")
    
    # Exchange the code for tokens
    redirect_uri = "http://localhost:8000/auth/google/callback"
    token_url = "https://oauth2.googleapis.com/token"
    
    # Get client secret from environment
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_secret:
        return RedirectResponse("/?error=missing_client_secret")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri
            }
        )
        
        if response.status_code != 200:
            return RedirectResponse(f"/?error=token_exchange_failed&details={response.text}")
        
        tokens = response.json()
        
        # Store tokens in session
        if "id_token" in tokens:
            request.session["id_token"] = tokens["id_token"]
        if "access_token" in tokens:
            request.session["access_token"] = tokens["access_token"]
        
        # Mark this as server-side auth
        request.session["auth_method"] = "Server-side authentication (authorization code flow)"
        
        # Get user info
        user_info_response = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            request.session["user_info"] = user_info
        
        return RedirectResponse("/?login=success")

@app.post("/api/store-token")
async def store_token(request: Request):
    """Store the token in the session"""
    data = await request.json()
    
    # Store in session
    if "id_token" in data:
        request.session["id_token"] = data["id_token"]
        request.session["auth_method"] = "Client-side authentication with ID token"
    if "access_token" in data:
        request.session["access_token"] = data["access_token"]
        request.session["auth_method"] = "Client-side authentication with access token"
    
    return {"status": "success"}

@app.get("/api/auth-method")
async def get_auth_method(request: Request):
    """Get the authentication method used"""
    if "auth_method" in request.session:
        return {"method": request.session["auth_method"]}
    return {"method": "Unknown authentication method"}

@app.get("/api/logout")
async def logout(request: Request):
    """Clear the session and redirect to home"""
    request.session.clear()
    return RedirectResponse("/")

@app.post("/api/logout")
async def logout_api(request: Request):
    """Clear the session"""
    request.session.clear()
    return {"status": "success"}

@app.get("/api/user-info")
async def get_user_info(request: Request):
    """Get user info from the session"""
    # Check if we have user info directly
    if "user_info" in request.session:
        return request.session["user_info"]
    
    # Check if we have a token
    if "id_token" not in request.session and "access_token" not in request.session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    # If we have an access token, use it to get user info
    if "access_token" in request.session:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {request.session['access_token']}"}
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
    
    # If we have an ID token, decode it
    if "id_token" in request.session:
        # This is a simplified JWT decoding for demo purposes
        # In production, you should verify the token signature
        token_parts = request.session["id_token"].split(".")
        if len(token_parts) != 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        
        import base64
        # Decode the payload (second part)
        payload = token_parts[1]
        # Add padding if needed
        payload += "=" * ((4 - len(payload) % 4) % 4)
        try:
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error decoding token: {str(e)}"
            )

# Run the app
if __name__ == "__main__":
    # Update .env file with instructions if GOOGLE_CLIENT_ID is not set
    if not GOOGLE_CLIENT_ID:
        env_path = Path(".env")
        if env_path.exists():
            with open(env_path, "a") as f:
                f.write("\n# Add your Google Client ID below\n# GOOGLE_CLIENT_ID=your-client-id-here\n")
        else:
            with open(env_path, "w") as f:
                f.write("# Add your Google Client ID below\nGOOGLE_CLIENT_ID=your-client-id-here\n")
        print("Added GOOGLE_CLIENT_ID placeholder to .env file")
    
    print(f"Google Client ID: {GOOGLE_CLIENT_ID or 'Not configured'}")
    uvicorn.run("google_test:app", host="0.0.0.0", port=8000, reload=True) 
