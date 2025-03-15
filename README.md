# OAuth Silent Authentication Playgrounds

This repository contains test playgrounds for experimenting with silent authentication capabilities for both Google and Twitter OAuth flows using FastAPI.

## Overview

Silent authentication allows applications to verify if a user is already logged in without requiring user interaction. This is particularly useful for:

- Checking authentication status without disrupting user experience
- Implementing "remember me" functionality
- Seamlessly refreshing tokens in the background
- Single sign-on (SSO) implementations

## Playgrounds Included

### 1. Google Authentication Playground

Tests Google's OAuth 2.0 implementation with both standard and silent authentication flows:

- **Client-side flow**: Uses Google's JavaScript library with client ID only
- **Server-side flow**: Uses authorization code flow with client secret
- **Silent authentication**: Implements `prompt=none` parameter to check if user is already authenticated

### 2. Twitter Authentication Playground

Tests Twitter's OAuth implementations with both standard and silent authentication flows:

- **OAuth 2.0**: Modern authentication flow used by Twitter API v2
- **OAuth 1.0a**: Legacy authentication flow with both authorize and authenticate endpoints
- **Silent authentication**: Uses hidden iframes to check authentication status without user interaction

## Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure your OAuth credentials**:
   - Create developer accounts with Google and Twitter
   - Set up projects/apps and enable OAuth
   - Configure the callback URLs to point to your local server (https://localhost:8000/callback)
   - Edit the `.env` file with your credentials:
     ```
     # Google OAuth credentials
     GOOGLE_CLIENT_ID=your_google_client_id_here
     GOOGLE_CLIENT_SECRET=your_google_client_secret_here
     
     # Twitter OAuth credentials
     TWITTER_CLIENT_ID=your_twitter_client_id_here
     TWITTER_CLIENT_SECRET=your_twitter_client_secret_here
     TWITTER_CALLBACK_URL=https://localhost:8000/callback
     TWITTER_CONSUMER_KEY=your_twitter_consumer_key_here
     TWITTER_CONSUMER_SECRET=your_twitter_consumer_secret_here
     
     # Session security
     SESSION_SECRET=generate_a_random_secret_here
     ```

3. **Run the server**:
   ```bash
   python main.py
   ```
   The application will automatically generate self-signed SSL certificates for localhost.

4. **Access the playgrounds**:
   - Twitter Auth: Open your browser and navigate to `https://localhost:8000/`
   - Note: Since the application uses self-signed certificates, you'll need to accept the security warning in your browser.

## Self-Signed Certificates

This application now generates self-signed SSL certificates automatically using Python's cryptography library. No external tools like mkcert are required. The certificates are generated when you first run the application and are saved as:

- `localhost.crt` - The certificate file
- `localhost.key` - The private key file

These files will be reused on subsequent runs. If you need to regenerate the certificates, simply delete these files and restart the application.

## How Silent Authentication Works

### Google Silent Authentication

Google's silent authentication uses the `prompt=none` parameter in the OAuth request:

1. When you click "Silent Login", the application initializes Google's OAuth client
2. It requests an access token with `prompt=none`, preventing any UI from showing
3. If the user is already logged into Google AND has previously authorized your app, Google returns a token without user interaction
4. If authentication fails silently (user not logged in or hasn't authorized), an error is returned

### Twitter Silent Authentication

Twitter's silent authentication uses hidden iframes:

1. When you click "Silent Check", a hidden iframe is created
2. The iframe attempts to authenticate with Twitter without user interaction
3. If the user is already logged into Twitter and has previously authorized your app, Twitter may automatically redirect back with an authorization code
4. The result is communicated back to the parent window using `postMessage`
5. Both OAuth 1.0a and OAuth 2.0 flows are supported

## Expected Behaviors

- **Successful Silent Auth**: If the user is already logged in AND has previously authorized your app, the check succeeds without showing any UI.
- **Silent Auth Requiring Consent**: If the user is logged in but hasn't authorized your app, a consent screen may appear (which might not be visible in hidden iframes).
- **Failed Silent Auth**: If the user isn't logged in or other issues occur, the silent check will fail with an appropriate error.

## Limitations

- OAuth providers might change their behavior regarding silent authentication at any time
- Success rates depend on user's browser settings, login status, and prior authorization
- These are meant as testbenches, not production-ready solutions
- Some browsers have restrictions on third-party cookies that may affect silent authentication

## Customization

- Modify the scopes in the OAuth handlers to match your use case
- Adjust timeout durations in the JavaScript for silent checks
- Add additional endpoints as needed for your specific requirements
