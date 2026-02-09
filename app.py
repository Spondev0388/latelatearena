from flask import Flask, render_template, redirect, url_for, session, request
import requests
import os

# --- NEW SECURITY IMPORTS ---
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- 1. SETUP RATE LIMITER ---
# This limits requests based on the user's IP address
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Global default
    storage_uri="memory://"  # Uses RAM. For production (Vercel/Heroku), use Redis.
)

# --- 2. SETUP CSRF PROTECTION ---
csrf = CSRFProtect(app)

# --- DAUTH CONFIGURATION ---
DAUTH_CLIENT_ID = 'Q~NtUatrs8lh-Sop'
DAUTH_CLIENT_SECRET = 'q4LaRjxVVLKcSFvq8D*=8FepDhb_TklZx'
DAUTH_REDIRECT_URI = 'http://localhost:5000/callback'
DAUTH_AUTH_URL = 'https://auth.delta.nitt.edu/authorize'
DAUTH_TOKEN_URL = 'https://auth.delta.nitt.edu/api/oauth/token'
DAUTH_USER_URL = 'https://auth.delta.nitt.edu/api/resources/user'


@app.route('/')
# Allow more traffic to the homepage (e.g., 5 requests per second)
@limiter.limit("5 per second")
def home():
    return render_template('index.html', roll_no=session.get('roll_no'))


@app.route('/login')
# STRICT LIMIT: Prevent button spamming (e.g., 10 attempts per minute)
@limiter.limit("10 per minute")
def login():
    auth_query = (
        f"{DAUTH_AUTH_URL}"
        f"?client_id={DAUTH_CLIENT_ID}"
        f"&redirect_uri={DAUTH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=email+profile+openid"
        f"&grant_type=authorization_code"
    )
    return redirect(auth_query)


@app.route('/callback')
@limiter.limit("10 per minute")
def callback():
    code = request.args.get('code')
    if not code:
        return "Login failed: No code received", 400

    # Exchange code for token
    data = {
        'client_id': DAUTH_CLIENT_ID,
        'client_secret': DAUTH_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'redirect_uri': DAUTH_REDIRECT_URI,
        'code': code
    }

    token_response = requests.post(DAUTH_TOKEN_URL, data=data)
    token_json = token_response.json()

    if 'access_token' not in token_json:
        return f"Token Error: {token_json}", 400

    access_token = token_json['access_token']

    # Get User Details
    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.post(DAUTH_USER_URL, headers=headers)
    user_data = user_response.json()

    # Logic to get Roll No
    email = user_data.get('email', '')
    if '@nitt.edu' in email:
        roll_no = email.split('@')[0]
        session['roll_no'] = roll_no
    else:
        session['roll_no'] = email

    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Handle Rate Limit Errors Gracefully
@app.errorhandler(429)
def ratelimit_handler(e):
    return "You are doing that too often. Chill for a minute.", 429


if __name__ == '__main__':
    app.run(debug=True, port=5000)
