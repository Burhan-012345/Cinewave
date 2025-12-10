# oauth.py - FIXED VERSION
from flask import Blueprint, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from models import db, User, Profile, PasswordHistory, OAuth
from werkzeug.security import generate_password_hash
import uuid
from datetime import datetime

# Create OAuth blueprint
oauth_bp = Blueprint('oauth', __name__)

def init_oauth(app):
    """Initialize OAuth with app configuration"""
    # Create Google blueprint
    google_bp = make_google_blueprint(
        client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
        client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
        scope=["openid", "email", "profile"],
        redirect_to="dashboard",  # Where to redirect after successful login
        storage=SQLAlchemyStorage(
            OAuth,
            db.session,
            user=current_user,
            user_required=False,
        ),
    )
    
    # Register the blueprint with a URL prefix
    app.register_blueprint(google_bp, url_prefix="/login/google")

    @oauth_bp.route("/google")
    def google_login_redirect():
        """Redirect to Google OAuth login"""
        try:
            # Redirect to Flask-Dance's Google OAuth endpoint
            return redirect(url_for("google.login"))
        except Exception as e:
            current_app.logger.error(f"Error redirecting to Google OAuth: {str(e)}")
            flash("Error initiating Google login. Please try again.", "danger")
            return redirect(url_for("login"))
    
    # Register signal handlers
    @oauth_authorized.connect_via(google_bp)
    def google_logged_in(blueprint, token):
        """Handle successful Google OAuth login"""
        if not token:
            flash("Failed to log in with Google: No token received.", "danger")
            return False
        
        try:
            # Get user info from Google
            resp = blueprint.session.get("https://www.googleapis.com/oauth2/v1/userinfo")
            if not resp.ok:
                flash("Failed to fetch user info from Google.", "danger")
                return False
            
            user_info = resp.json()
            
            # Extract user data
            email = user_info.get("email")
            name = user_info.get("name", email.split('@')[0]) if email else "Google User"
            google_id = user_info.get("id")
            
            if not email:
                flash("Email not provided by Google.", "danger")
                return False
            
            # Check if user already exists by email
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Create new user
                user = User(
                    email=email,
                    name=name,
                    password_hash=generate_password_hash(str(uuid.uuid4())),
                    is_active=True,
                    email_verified=True
                )
                db.session.add(user)
                db.session.flush()  # Get the user ID without committing
                
                # Create default profile
                profile = Profile(
                    user_id=user.id,
                    name=name or "Main Profile",
                    is_default=True
                )
                db.session.add(profile)
                
                # Store password in history
                password_history = PasswordHistory(
                    user_id=user.id,
                    password_hash=user.password_hash
                )
                db.session.add(password_history)
                
                flash("Account created successfully with Google!", "success")
            
            # Check if OAuth connection already exists
            oauth = OAuth.query.filter_by(
                provider="google",
                provider_user_id=google_id
            ).first()
            
            if not oauth:
                # Create new OAuth connection
                oauth = OAuth(
                    provider="google",
                    provider_user_id=google_id,
                    user_id=user.id,
                    token=token
                )
                db.session.add(oauth)
            else:
                # Update existing token
                oauth.token = token
            
            db.session.commit()
            
            # Login the user
            login_user(user)
            flash(f"Welcome, {name}! Successfully logged in with Google.", "success")
            
            # Return False to let Flask-Dance handle the redirect
            return False
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Google OAuth error: {str(e)}")
            flash(f"Error during Google login: {str(e)}", "danger")
            return False
    
    @oauth_error.connect_via(google_bp)
    def google_error(blueprint, error, error_description=None, error_uri=None):
        """Handle Google OAuth errors"""
        msg = f"Google login failed: {error}"
        if error_description:
            msg += f" ({error_description})"
        flash(msg, "danger")
        return redirect(url_for("login"))
    
    # Add a route to handle OAuth callback directly if needed
    @oauth_bp.route("/callback")
    def oauth_callback():
        """Handle OAuth callback - redirect to appropriate page"""
        # This route can handle any post-OAuth processing if needed
        return redirect(url_for("dashboard"))