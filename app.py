import os
import re
import random
import string
import uuid
import tempfile
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

from flask import Flask, Response, current_app, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_admin import Admin
from flask_wtf.csrf import CSRFProtect, generate_csrf
from utils.download_utils import (
    check_download_limits, 
    generate_download_token, 
    verify_download_token, 
    allowed_file, 
    create_placeholder_movie_file,
    verify_movie_file_exists, 
    format_file_size  
)

# ========================================
# APP INITIALIZATION
# ========================================

app = Flask(__name__)
app.config.from_object('config.Config')

# ========================================
# CONFIGURE UPLOAD FOLDERS (IMMEDIATELY AFTER APP CREATION)
# ========================================

# Configure upload folders
app.config['MOVIE_UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'movie_files')
app.config['POSTER_UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'posters')
app.config['TRAILER_UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'trailers')

app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm'}
app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 * 1024  # 4GB max file size

# ========================================
# HELPER FUNCTIONS (DEFINED AFTER CONFIG)
# ========================================

def ensure_upload_directories():
    """Ensure all upload directories exist"""
    directories = [
        app.config['MOVIE_UPLOAD_FOLDER'],
        app.config['POSTER_UPLOAD_FOLDER'],
        app.config['TRAILER_UPLOAD_FOLDER'],
        os.path.join(app.instance_path, 'temp'),
        os.path.join(app.root_path, 'static', 'uploads', 'movies'),
        os.path.join(app.root_path, 'static', 'uploads', 'posters'),
        os.path.join(app.root_path, 'static', 'uploads', 'trailers'),
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    return directories

# ========================================
# CREATE DIRECTORIES
# ========================================

with app.app_context():
    ensure_upload_directories()

# ========================================
# CONTINUE WITH THE REST OF YOUR IMPORTS AND SETUP
# ========================================

from admin.admin_setup import setup_admin
from models import db
from utils.download_utils import check_download_limits, generate_download_token, verify_download_token, allowed_file, create_placeholder_movie_file
from utils.email_utils import send_otp_email, send_reset_link_email
from models.oauth import oauth_bp, init_oauth

# Initialize extensions
mail = Mail(app)  
csrf = CSRFProtect(app)

init_oauth(app)
app.register_blueprint(oauth_bp)

db.init_app(app)
mail.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
admin = Admin(app, name='CineWave Admin', template_mode='bootstrap3')
setup_admin(admin, db)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import models after db initialization
with app.app_context():
    from models import User, Profile, Movie, Genre, Review, Watchlist, ContinueWatching, PasswordHistory, ResetToken, MovieDownload

# ========================================
# GLOBAL VARIABLES AND CONTEXT PROCESSORS
# ========================================

@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.utcnow()}

@app.context_processor
def inject_config():
    """Inject config variables into templates"""
    return {
        'MAX_DOWNLOADS_PER_DAY': app.config.get('MAX_DOWNLOADS_PER_DAY', 10),
        'DOWNLOAD_EXPIRY_DAYS': app.config.get('DOWNLOAD_EXPIRY_DAYS', 30)
    }

@app.template_filter('format_time')
def format_time_filter(seconds):
    """Format seconds to HH:MM:SS or MM:SS"""
    if not seconds:
        return "0:00"
    
    try:
        seconds = int(seconds)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        
        if hours > 0:
            return f"{hours}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{minutes}:{seconds:02d}"
    except (ValueError, TypeError):
        return "0:00"

@app.template_filter('format_file_size')
def format_file_size_filter(bytes):
    """Convert bytes to human-readable file size"""
    if bytes is None:
        return "N/A"
    
    try:
        bytes = float(bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} TB"
    except (TypeError, ValueError):
        return "N/A"
def allowed_image_file(filename):
    """Check if file is an allowed image type"""
    if not filename or '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    allowed = app.config.get('ALLOWED_IMAGE_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif', 'webp'})
    return ext in allowed

def allowed_video_file(filename):
    """Check if file is an allowed video type"""
    if not filename or '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    allowed = app.config.get('ALLOWED_EXTENSIONS', {'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm'})
    return ext in allowed

def serve_movie_file_fallback(movie):
    """Serve movie file with proper error handling - FIXED VERSION"""
    try:
        # Use the improved verification function
        from utils.download_utils import verify_movie_file_exists, is_video_file
        
        file_exists, file_path = verify_movie_file_exists(movie)
        
        if not file_exists or not is_video_file(file_path):
            # Check if we found a file but it's not a video
            if file_path and os.path.exists(file_path):
                # Read first few bytes to confirm it's not a video
                with open(file_path, 'rb') as f:
                    first_bytes = f.read(100)
                    if b'cinewave' in first_bytes.lower() or b'placeholder' in first_bytes.lower():
                        current_app.logger.warning(f"Found placeholder text file instead of video: {file_path}")
            
            # Create a proper video placeholder
            from utils.download_utils import create_video_placeholder
            temp_file = create_video_placeholder(movie)
            flash('Actual movie file not found. Serving placeholder video for demonstration.', 'info')
            return send_file(
                temp_file,
                as_attachment=False,
                download_name=f"CineWave_{movie.title.replace(' ', '_')}_{movie.release_year}.mp4",
                mimetype='video/mp4'
            )
        
        # Verify it's actually a video file
        if not is_video_file(file_path):
            flash('Found file but it appears to be corrupted or not a valid video.', 'warning')
            return redirect(url_for('movie_detail', movie_id=movie.id))
        
        # Serve the actual file
        filename = os.path.basename(file_path)
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Set correct MIME type
        mime_types = {
            '.mp4': 'video/mp4',
            '.mkv': 'video/x-matroska',
            '.avi': 'video/x-msvideo',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.flv': 'video/x-flv',
            '.webm': 'video/webm',
        }
        mime_type = mime_types.get(file_ext, 'video/mp4')
        
        # Log for debugging
        current_app.logger.info(f"Serving video file: {file_path} ({mime_type})")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"CineWave_{movie.title.replace(' ', '_')}_{movie.release_year}{file_ext}",
            mimetype=mime_type
        )
        
    except Exception as e:
        current_app.logger.error(f"Error serving file: {str(e)}")
        flash(f'Error serving file: {str(e)}', 'danger')
        return redirect(url_for('movie_detail', movie_id=movie.id))
    
def format_file_size(bytes):
    """Convert bytes to human-readable file size"""
    if bytes is None:
        return "N/A"
    
    bytes = float(bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"

def ensure_upload_directories():
    """Ensure all upload directories exist"""
    directories = [
        app.config['MOVIE_UPLOAD_FOLDER'],
        app.config['POSTER_UPLOAD_FOLDER'],
        app.config['TRAILER_UPLOAD_FOLDER'],
        os.path.join(app.instance_path, 'temp'),
        os.path.join(app.root_path, 'static', 'uploads', 'movies'),
        os.path.join(app.root_path, 'static', 'uploads', 'posters'),
        os.path.join(app.root_path, 'static', 'uploads', 'trailers'),
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    return directories

# ========================================
# INTRO PAGE & HOME ROUTES
# ========================================

@app.route('/')
def home():
    """Show intro page for first-time visitors, otherwise movies index"""
    # Check if user has seen intro before
    intro_shown = session.get('intro_shown', False)
    
    if not intro_shown and not current_user.is_authenticated:
        # Show intro page for new visitors
        return render_template('intro.html')
    else:
        # Mark intro as shown for this session
        session['intro_shown'] = True
        return redirect(url_for('movies_index'))

@app.route('/skip_intro')
def skip_intro():
    """Skip intro and mark as shown"""
    session['intro_shown'] = True
    return redirect(url_for('movies_index'))

# ========================================
# PASSWORD RESET ROUTES
# ========================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password request"""
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            token = serializer.dumps(user.email, salt='password-reset-salt')
            
            # Create reset token record
            reset_token = ResetToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # Send reset email
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_link_email(user.email, reset_url, app)
            
            flash('Password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found in our system.', 'danger')
    
    return render_template('AUTH/forgot_password.html')

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP for registration or password reset"""
    data = request.get_json()
    otp_type = data.get('type', 'registration') 
    
    if otp_type == 'registration':
        return resend_registration_otp()
    elif otp_type == 'reset':
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'error': 'Email not found'}), 404
        
        # Generate new OTP for password reset
        otp = ''.join(random.choices(string.digits, k=6))
        session['reset_otp'] = otp
        session['reset_email'] = email
        session['reset_otp_time'] = datetime.utcnow().timestamp()
        
        try:
            send_otp_email(email, otp, app)
            return jsonify({'success': True, 'message': 'Reset OTP sent successfully!'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return jsonify({'success': False, 'error': 'Invalid OTP type'}), 400
        
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    try:
        # Verify token
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        reset_token = ResetToken.query.filter_by(token=token, used=False).first()
        
        if not user or not reset_token or reset_token.expires_at < datetime.utcnow():
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Basic validation
            if not new_password or not confirm_password:
                flash('Please fill in all fields.', 'danger')
                return redirect(request.url)
            
            if new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return redirect(request.url)
            
            # Check password requirements
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return redirect(request.url)
            
            # Check if password is the same as old passwords
            old_passwords = PasswordHistory.query.filter_by(user_id=user.id).all()
            for old_password in old_passwords:
                if check_password_hash(old_password.password_hash, new_password):
                    flash('Cannot use a previous password.', 'danger')
                    return redirect(request.url)
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            
            # Add to password history
            password_history = PasswordHistory(
                user_id=user.id,
                password_hash=generate_password_hash(new_password)
            )
            db.session.add(password_history)
            
            # Mark token as used
            reset_token.used = True
            reset_token.used_at = datetime.utcnow()
            
            db.session.commit()
            
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        
        return render_template('AUTH/reset_password.html', token=token)
        
    except SignatureExpired:
        flash('The reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link.', 'danger')
        return redirect(url_for('forgot_password'))
    
@app.route('/send-registration-otp', methods=['POST'])
def send_registration_otp():
    """Send OTP for email verification during registration"""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # Validate email format
        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_regex, email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # Store OTP in session with timestamp
        session['registration_otp'] = otp
        session['registration_email'] = email
        session['registration_otp_time'] = datetime.utcnow().timestamp()
        
        # Send OTP email
        try:
            send_otp_email(email, otp, app)
            
            # Store registration attempt for rate limiting
            if 'registration_attempts' not in session:
                session['registration_attempts'] = {}
            
            session['registration_attempts'][email] = session['registration_attempts'].get(email, 0) + 1
            
            return jsonify({
                'success': True, 
                'message': 'OTP sent successfully!',
                'email': email
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': 'Failed to send OTP. Please try again.'}), 500

@app.route('/verify-registration-otp', methods=['POST'])
def verify_registration_otp():
    """Verify OTP for email verification during registration"""
    if request.method == 'POST':
        data = request.get_json()
        otp = data.get('otp')
        email = session.get('registration_email')
        
        if not otp or not email:
            return jsonify({'success': False, 'error': 'OTP and email are required'}), 400
        
        stored_otp = session.get('registration_otp')
        otp_time = session.get('registration_otp_time')
        
        # Check if OTP exists and is not expired (10 minutes)
        if not stored_otp or not otp_time:
            return jsonify({'success': False, 'error': 'No OTP found. Please request a new one.'}), 400
        
        # Check OTP expiry (10 minutes)
        time_elapsed = datetime.utcnow().timestamp() - otp_time
        if time_elapsed > 600:  # 10 minutes in seconds
            session.pop('registration_otp', None)
            session.pop('registration_otp_time', None)
            return jsonify({'success': False, 'error': 'OTP has expired. Please request a new one.'}), 400
        
        # Verify OTP
        if stored_otp != otp:
            # Increment failed attempts
            if 'otp_failed_attempts' not in session:
                session['otp_failed_attempts'] = 0
            session['otp_failed_attempts'] += 1
            
            # Clear OTP after 3 failed attempts
            if session['otp_failed_attempts'] >= 3:
                session.pop('registration_otp', None)
                session.pop('registration_otp_time', None)
                session.pop('otp_failed_attempts', None)
                return jsonify({'success': False, 'error': 'Too many failed attempts. Please request a new OTP.'}), 400
            
            return jsonify({'success': False, 'error': 'Invalid OTP. Please try again.'}), 400
        
        # OTP verified successfully
        session['registration_verified'] = True
        session.pop('otp_failed_attempts', None)  # Clear failed attempts counter
        
        return jsonify({
            'success': True, 
            'message': 'Email verified successfully!',
            'email': email
        })

@app.route('/register/finalize', methods=['POST'])
def register_finalize():
    """Finalize registration after email verification"""
    if request.method == 'POST':
        # Check if email is verified
        if not session.get('registration_verified'):
            return jsonify({'success': False, 'error': 'Email not verified'}), 400
        
        email = session.get('registration_email')
        name = request.form.get('name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not all([email, name, password, confirm_password]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
        
        # Check password requirements
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters long'}), 400
        
        # Check if password has uppercase, lowercase, number, and special char
        if not (any(c.isupper() for c in password) and 
                any(c.islower() for c in password) and 
                any(c.isdigit() for c in password) and
                any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`"' for c in password)):
            return jsonify({
                'success': False, 
                'error': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            }), 400
        
        # Check if user already exists (double-check)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # Clear session
            session.pop('registration_email', None)
            session.pop('registration_verified', None)
            session.pop('registration_otp', None)
            session.pop('registration_otp_time', None)
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create user
        try:
            user = User(
                email=email,
                name=name,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            
            # Create default profile
            profile = Profile(
                user_id=user.id,
                name="Main Profile",
                is_default=True
            )
            db.session.add(profile)
            db.session.commit()
            
            # Store password in history
            password_history = PasswordHistory(
                user_id=user.id,
                password_hash=generate_password_hash(password)
            )
            db.session.add(password_history)
            db.session.commit()
            
            # Clear registration session data
            session.pop('registration_email', None)
            session.pop('registration_verified', None)
            session.pop('registration_otp', None)
            session.pop('registration_otp_time', None)
            session.pop('registration_attempts', None)
            
            # Auto-login the user
            login_user(user)
            
            # Check if there's a movie waiting for download
            download_movie_id = session.get('download_movie_id')
            if download_movie_id:
                session.pop('download_movie_id', None)
                return jsonify({
                    'success': True, 
                    'message': 'Registration successful! Starting your download...',
                    'redirect': url_for('prepare_download', movie_id=download_movie_id)
                })
            
            return jsonify({
                'success': True, 
                'message': 'Registration successful!',
                'redirect': url_for('dashboard')
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Registration failed. Please try again.'}), 500

# Update the existing register route to work with the new flow
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle registration with email verification"""
    if request.method == 'POST':
        # Check if this is the final registration step
        if request.form.get('final_step') == 'true':
            return register_finalize()
        
        # Otherwise, this is the initial form submission for OTP
        email = request.form.get('email')
        name = request.form.get('name')
        
        # Store in session for later use
        session['temp_name'] = name
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # Store in session
        session['registration_otp'] = otp
        session['registration_email'] = email
        session['registration_name'] = name
        session['registration_otp_time'] = datetime.utcnow().timestamp()
        
        # Send OTP email
        try:
            send_otp_email(email, otp, app)
            flash('OTP sent to your email. Please verify to continue.', 'info')
        except Exception as e:
            flash('Failed to send OTP. Please try again.', 'danger')
        
        return redirect(url_for('register'))
    
    # GET request - render registration form
    return render_template('AUTH/register.html')

# Add a cleanup route for expired registration sessions
@app.route('/clear-registration-session', methods=['POST'])
def clear_registration_session():
    """Clear registration session data"""
    session.pop('registration_email', None)
    session.pop('registration_verified', None)
    session.pop('registration_otp', None)
    session.pop('registration_otp_time', None)
    session.pop('registration_name', None)
    session.pop('temp_name', None)
    session.pop('registration_attempts', None)
    session.pop('otp_failed_attempts', None)
    
    return jsonify({'success': True, 'message': 'Session cleared'})

# Add this route to handle resending OTP for registration
@app.route('/resend-registration-otp', methods=['POST'])
def resend_registration_otp():
    """Resend OTP for registration"""
    email = session.get('registration_email')
    
    if not email:
        return jsonify({'success': False, 'error': 'No registration in progress'}), 400
    
    # Check rate limiting
    attempts = session.get('registration_attempts', {}).get(email, 0)
    if attempts >= 5:
        return jsonify({'success': False, 'error': 'Too many attempts. Please try again later.'}), 429
    
    # Generate new OTP
    otp = ''.join(random.choices(string.digits, k=6))
    session['registration_otp'] = otp
    session['registration_otp_time'] = datetime.utcnow().timestamp()
    
    # Update attempts
    if 'registration_attempts' not in session:
        session['registration_attempts'] = {}
    session['registration_attempts'][email] = attempts + 1
    
    # Send OTP email
    try:
        send_otp_email(email, otp, app)
        return jsonify({
            'success': True, 
            'message': 'OTP resent successfully!',
            'attempts_left': 5 - (attempts + 1)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get user's current active profile
    current_profile = Profile.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).first()
    
    # If no active profile, get the default one
    if not current_profile:
        current_profile = Profile.query.filter_by(
            user_id=current_user.id,
            is_default=True
        ).first()
    
    # Get user's watchlist
    watchlist_items = Watchlist.query.filter_by(user_id=current_user.id).all()
    watchlist_movie_ids = [item.movie_id for item in watchlist_items]
    
    # Get continue watching
    continue_watching_items = []
    if current_profile:
        continue_watching_items = ContinueWatching.query.filter_by(
            profile_id=current_profile.id
        ).order_by(ContinueWatching.updated_at.desc()).limit(4).all()
    
    # Get recent downloads
    recent_downloads = MovieDownload.query.filter_by(
        user_id=current_user.id,
        status='completed'
    ).order_by(MovieDownload.completed_at.desc()).limit(5).all()
    
    # Get recommendations (simplified for now)
    recommendations = Movie.query.order_by(Movie.views_count.desc()).limit(6).all()
    
    return render_template('USER/dashboard.html',
                         profile=current_profile,
                         watchlist=watchlist_items,  
                         continue_watching=continue_watching_items,
                         recent_downloads=recent_downloads,
                         recommendations=recommendations)

@app.route('/analytics')
@login_required
def analytics():
    """User analytics and statistics dashboard"""
    # Get user's current active profile
    current_profile = Profile.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).first()
    
    # Get user statistics
    total_watchlist = Watchlist.query.filter_by(user_id=current_user.id).count()
    total_reviews = Review.query.filter_by(user_id=current_user.id).count()
    total_downloads = MovieDownload.query.filter_by(
        user_id=current_user.id,
        status='completed'
    ).count()
    
    # Get continue watching stats
    continue_watching_count = 0
    if current_profile:
        continue_watching_count = current_profile.continue_watching_count
    
    # Get recent activity
    recent_activity = []
    
    # Recent downloads
    recent_downloads = MovieDownload.query.filter_by(
        user_id=current_user.id,
        status='completed'
    ).order_by(MovieDownload.completed_at.desc()).limit(5).all()
    for dl in recent_downloads:
        recent_activity.append({
            'type': 'download',
            'title': dl.movie.title if dl.movie else 'Unknown Movie',
            'timestamp': dl.completed_at,
            'icon': 'fas fa-download'
        })
    
    # Recent reviews
    recent_reviews = Review.query.filter_by(
        user_id=current_user.id
    ).order_by(Review.created_at.desc()).limit(5).all()
    for review in recent_reviews:
        recent_activity.append({
            'type': 'review',
            'title': f"Reviewed: {review.movie.title if review.movie else 'Unknown Movie'}",
            'timestamp': review.created_at,
            'icon': 'fas fa-star',
            'rating': review.rating
        })
    
    # Sort recent activity by timestamp
    recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activity = recent_activity[:10]  # Limit to 10 most recent
    
    # Get genre preferences
    watchlist_movies = Watchlist.query.filter_by(user_id=current_user.id).all()
    genre_counts = {}
    for item in watchlist_movies:
        if item.movie and item.movie.genres:
            for genre in item.movie.genres:
                genre_counts[genre.name] = genre_counts.get(genre.name, 0) + 1
    
    # Sort genres by count
    sorted_genres = sorted(genre_counts.items(), key=lambda x: x[1], reverse=True)
    
    return render_template('admin/analytics.html',
                         profile=current_profile,
                         total_watchlist=total_watchlist,
                         total_reviews=total_reviews,
                         total_downloads=total_downloads,
                         continue_watching_count=continue_watching_count,
                         recent_activity=recent_activity,
                         genre_preferences=sorted_genres[:5],  # Top 5 genres
                         now=datetime.utcnow())

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    """Admin analytics dashboard"""
    # Check if user is admin
    if not current_user.is_admin:
        abort(403)
    
    # Import models (if not already imported)
    from models import User, Profile, Movie, Review, Watchlist, ContinueWatching, MovieDownload
    
    # Calculate statistics
    total_users = User.query.count()
    total_movies = Movie.query.count()
    total_reviews = Review.query.count()
    
    # Calculate total watch time from ContinueWatching records
    total_watch_time = 0
    continue_watching_items = ContinueWatching.query.all()
    for item in continue_watching_items:
        if item.current_time:
            total_watch_time += item.current_time
    
    # Get recent activity (last 24 hours)
    recent_activity = []
    cutoff_time = datetime.utcnow() - timedelta(hours=24)
    
    # Recent registrations
    new_users = User.query.filter(User.created_at >= cutoff_time).all()
    for user in new_users:
        recent_activity.append({
            'type': 'registration',
            'description': f'New user registered: {user.email}',
            'user': user.name,
            'time': user.created_at
        })
    
    # Recent reviews
    new_reviews = Review.query.filter(Review.created_at >= cutoff_time).all()
    for review in new_reviews:
        movie_title = review.movie.title if review.movie else "Unknown Movie"
        user_name = review.user.name if review.user else 'Unknown'
        recent_activity.append({
            'type': 'review',
            'description': f'New review for {movie_title}',
            'user': user_name,
            'time': review.created_at
        })
    
    # Recent downloads
    new_downloads = MovieDownload.query.filter(
        MovieDownload.created_at >= cutoff_time,
        MovieDownload.status == 'completed'
    ).all()
    for download in new_downloads:
        movie_title = download.movie.title if download.movie else "Unknown"
        user_name = download.user.name if download.user else 'Unknown'
        recent_activity.append({
            'type': 'download',
            'description': f'Movie downloaded: {movie_title}',
            'user': user_name,
            'time': download.completed_at or download.created_at
        })
    
    # Sort by time (most recent first)
    recent_activity.sort(key=lambda x: x['time'], reverse=True)
    
    # Calculate additional statistics
    total_downloads = MovieDownload.query.filter_by(status='completed').count()
    
    # Get today's date (without time)
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_downloads = MovieDownload.query.filter(
        MovieDownload.status == 'completed',
        MovieDownload.completed_at >= today_start
    ).count()
    
    # Calculate active users (users with activity in last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    active_users = set()
    
    # Users who logged in recently (if you have last_login field)
    try:
        recent_logins = User.query.filter(User.last_login >= week_ago).all()
        for user in recent_logins:
            active_users.add(user.id)
    except:
        pass
    
    # Users with recent watchlist activity
    recent_watchlist = Watchlist.query.filter(Watchlist.created_at >= week_ago).all()
    for item in recent_watchlist:
        active_users.add(item.user_id)
    
    active_users_count = len(active_users)
    
    # Calculate average rating
    avg_rating = db.session.query(db.func.avg(Review.rating)).scalar() or 0
    avg_rating = round(avg_rating, 1)
    
    # Get profile count
    total_profiles = Profile.query.count()
    
    # Get watchlist count
    total_watchlist_items = Watchlist.query.count()
    
    # Get continue watching count
    total_continue_watching = ContinueWatching.query.count()
    
    # Get movies with files
    movies_with_files = Movie.query.filter(Movie.file_path.isnot(None)).count()
    
    # Get recent movies
    recent_movies = Movie.query.order_by(Movie.created_at.desc()).limit(5).all()
    
    return render_template('ADMIN/analytics.html',
                         total_users=total_users,
                         total_movies=total_movies,
                         total_reviews=total_reviews,
                         total_watch_time=total_watch_time,
                         recent_activity=recent_activity[:10],  
                         total_downloads=total_downloads,
                         today_downloads=today_downloads,
                         active_users_count=active_users_count,
                         avg_rating=avg_rating,
                         total_profiles=total_profiles,
                         total_watchlist_items=total_watchlist_items,
                         total_continue_watching=total_continue_watching,
                         movies_with_files=movies_with_files,
                         recent_movies=recent_movies)

@app.route('/continue-watching')
@login_required
def continue_watching():
    """Show all continue watching items for user"""
    # Get current active profile
    current_profile = Profile.query.filter_by(user_id=current_user.id, is_active=True).first()
    
    if not current_profile:
        flash('Please select a profile first.', 'warning')
        return redirect(url_for('profiles'))
    
    # Get all continue watching items for this profile
    continue_watching_items = ContinueWatching.query.filter_by(
        profile_id=current_profile.id
    ).order_by(ContinueWatching.updated_at.desc()).all()
    
    return render_template('USER/continue_watching.html',
                         continue_watching=continue_watching_items,
                         profile=current_profile)

@app.route('/profiles')
@login_required
def profiles():
    """Show all profiles for the current user"""
    user_profiles = Profile.query.filter_by(user_id=current_user.id).all()
    
    return render_template('USER/profiles.html', profiles=user_profiles)

@app.route('/profile/switch/<int:profile_id>')
@login_required
def switch_profile(profile_id):
    """Switch active profile"""
    profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    
    # Deactivate all profiles for this user
    Profile.query.filter_by(user_id=current_user.id).update({'is_active': False})
    
    # Activate selected profile
    profile.is_active = True
    db.session.commit()
    
    flash(f'Switched to profile: {profile.name}', 'success')
    return redirect(url_for('profiles'))

@app.route('/profile/create', methods=['POST'])
@login_required
def create_profile():
    """Create a new profile"""
    name = request.form.get('name', '').strip()
    is_child = 'is_child' in request.form
    
    if not name:
        flash('Profile name is required', 'danger')
        return redirect(url_for('profiles'))
    
    # Check max profiles (limit to 5 per user)
    profile_count = Profile.query.filter_by(user_id=current_user.id).count()
    if profile_count >= 5:
        flash('Maximum of 5 profiles reached', 'warning')
        return redirect(url_for('profiles'))
    
    # Create profile
    profile = Profile(
        user_id=current_user.id,
        name=name,
        is_child=is_child,
        is_active=False  # Don't auto-activate new profiles
    )
    
    # If this is the first profile, make it default and active
    if profile_count == 0:
        profile.is_default = True
        profile.is_active = True
    
    db.session.add(profile)
    db.session.commit()
    
    flash(f'Profile "{name}" created successfully!', 'success')
    return redirect(url_for('profiles'))

@app.route('/profile/delete/<int:profile_id>')
@login_required
def delete_profile(profile_id):
    """Delete a profile"""
    profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    
    # Cannot delete default profile
    if profile.is_default:
        flash('Cannot delete default profile', 'danger')
        return redirect(url_for('profiles'))
    
    # Cannot delete active profile
    if profile.is_active:
        flash('Cannot delete active profile. Switch to another profile first.', 'danger')
        return redirect(url_for('profiles'))
    
    profile_name = profile.name
    db.session.delete(profile)
    db.session.commit()
    
    flash(f'Profile "{profile_name}" deleted successfully', 'success')
    return redirect(url_for('profiles'))

@app.route('/movie/<int:movie_id>')
def movie_detail(movie_id):
    """Show movie details page"""
    from models import Movie, Review, Watchlist, ContinueWatching, Genre, MovieDownload, Profile
    
    movie = Movie.query.get_or_404(movie_id)
    reviews = Review.query.filter_by(movie_id=movie_id).all()

    # Initialize variables
    current_profile = None
    in_watchlist = False
    previous_download = None
    download_limits = {}
    continue_progress = None

    if current_user.is_authenticated:
        # Get current active profile
        current_profile = Profile.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).first()

        # Check if movie is in watchlist
        watchlist_item = Watchlist.query.filter_by(
            user_id=current_user.id, 
            movie_id=movie_id
        ).first()
        in_watchlist = watchlist_item is not None

        # Check for previous downloads
        previous_download = MovieDownload.query.filter_by(
            user_id=current_user.id,
            movie_id=movie_id,
            status='completed'
        ).order_by(MovieDownload.completed_at.desc()).first()

        # Check download limits
        from utils.download_utils import check_download_limits
        download_limits = check_download_limits(current_user.id)

        # Get continue watching progress if profile exists
        if current_profile:
            cw = ContinueWatching.query.filter_by(
                profile_id=current_profile.id, 
                movie_id=movie_id
            ).first()
            if cw:
                continue_progress = cw

    # Get similar movies based on genres
    similar_movies = []
    if movie.genres:
        genre_ids = [genre.id for genre in movie.genres]
        similar_movies = Movie.query.join(Movie.genres).filter(
            Genre.id.in_(genre_ids),
            Movie.id != movie_id
        ).distinct().limit(6).all()

    # Calculate average rating
    average_rating = 0
    if reviews:
        try:
            # Extract ratings safely
            ratings = []
            for review in reviews:
                if hasattr(review, 'rating') and review.rating is not None:
                    try:
                        ratings.append(float(review.rating))
                    except (ValueError, TypeError):
                        continue
            
            if ratings:
                average_rating = sum(ratings) / len(ratings)
        except (TypeError, AttributeError, ZeroDivisionError):
            average_rating = 0

    # Get watchlist count
    watchlist_count = 0
    if hasattr(movie, 'watchlist_items'):
        watchlist_count = len(movie.watchlist_items)
    else:
        # Fallback query if watchlist_items attribute doesn't exist
        watchlist_count = Watchlist.query.filter_by(movie_id=movie_id).count()

    return render_template('MOVIES/movie_detail.html',
                           movie=movie,
                           reviews=reviews,
                           in_watchlist=in_watchlist,
                           previous_download=previous_download,
                           similar_movies=similar_movies,
                           continue_progress=continue_progress,
                           download_limits=download_limits,
                           profile=current_profile,
                           average_rating=average_rating,
                           watchlist_count=watchlist_count)

@app.route('/logout')
@login_required
def logout():
    """Logout the current user"""
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/recommendations')
@login_required
def recommendations():
    """Movie recommendations for user"""
    try:
        # Get watchlist movies
        watchlist_items = Watchlist.query.filter_by(user_id=current_user.id).all()
        
        watchlist_movie_ids = []
        if watchlist_items:
            watchlist_movie_ids = [item.movie_id for item in watchlist_items if item.movie_id]
        
        recommendations_list = []
        
        if watchlist_movie_ids:
            # First, get all genres from watchlisted movies
            all_genre_ids = set()
            for movie_id in watchlist_movie_ids:
                movie = Movie.query.get(movie_id)
                if movie and movie.genres:
                    for genre in movie.genres:
                        if genre and hasattr(genre, 'id'):
                            all_genre_ids.add(genre.id)
            
            if all_genre_ids:
                # Get movies with similar genres (excluding already watchlisted)
                from sqlalchemy import and_, not_
                
                # Build the query for recommendations
                recommendations_query = Movie.query.join(movie_genre).filter(
                    movie_genre.c.genre_id.in_(list(all_genre_ids)),
                    Movie.id.notin_(watchlist_movie_ids)
                ).distinct()
                
                recommendations_list = recommendations_query.limit(20).all()
            
            # If we don't have enough recommendations, add popular movies
            if len(recommendations_list) < 12:
                popular_needed = 12 - len(recommendations_list)
                popular_movies = Movie.query.filter(
                    Movie.id.notin_(watchlist_movie_ids),
                    Movie.id.notin_([m.id for m in recommendations_list])
                ).order_by(
                    Movie.views_count.desc(),
                    Movie.download_count.desc()
                ).limit(popular_needed * 2).all()
                
                recommendations_list.extend(popular_movies)
        else:
            # If no watchlist, show popular movies
            recommendations_list = Movie.query.order_by(
                Movie.views_count.desc(),
                Movie.download_count.desc()
            ).limit(12).all()
        
        # Shuffle the recommendations for better UX
        import random
        random.shuffle(recommendations_list)
        recommendations_list = recommendations_list[:12]  # Limit to 12
        
        return render_template('MOVIES/recommendations.html', 
                             movies=recommendations_list,
                             watchlist_movie_ids=watchlist_movie_ids)
        
    except Exception as e:
        # Fallback: return popular movies
        recommendations_list = Movie.query.order_by(
            Movie.views_count.desc()
        ).limit(12).all()
        
        return render_template('MOVIES/recommendations.html', 
                             movies=recommendations_list,
                             watchlist_movie_ids=[])
    
@app.route('/movie/<int:movie_id>/stream')
@login_required
def stream_movie(movie_id):
    """Stream movie content"""
    movie = Movie.query.get_or_404(movie_id)
    
    # Check if user has access to this movie
    # Add premium/subscription checks here
    
    # Update views count
    movie.views_count += 1
    
    # Get current profile
    current_profile = Profile.query.filter_by(
        user_id=current_user.id, 
        is_active=True
    ).first()
    
    # Get user's watchlist IDs for the template
    watchlist_items = Watchlist.query.filter_by(user_id=current_user.id).all()
    watchlist_movie_ids = [item.movie_id for item in watchlist_items]
    
    # Get similar movies
    similar_movies = []
    if movie.genres:
        genre_ids = [genre.id for genre in movie.genres]
        similar_movies = Movie.query.join(Movie.genres).filter(
            Genre.id.in_(genre_ids),
            Movie.id != movie_id
        ).distinct().limit(6).all()
    
    # Get continue watching progress
    continue_progress = None
    if current_profile:
        continue_progress = ContinueWatching.query.filter_by(
            profile_id=current_profile.id,
            movie_id=movie_id
        ).first()
    
    # Update or create continue watching entry
    if current_profile:
        continue_watching = ContinueWatching.query.filter_by(
            profile_id=current_profile.id,
            movie_id=movie_id
        ).first()
        
        if continue_watching:
            continue_watching.updated_at = datetime.utcnow()
        else:
            continue_watching = ContinueWatching(
                profile_id=current_profile.id,
                movie_id=movie_id,
                current_time=0,
                duration=movie.duration * 60 if movie.duration else 7200
            )
            db.session.add(continue_watching)
    
    db.session.commit()
    
    return render_template('MOVIES/stream.html', 
                         movie=movie,
                         profile=current_profile,
                         watchlist_movie_ids=watchlist_movie_ids,
                         similar_movies=similar_movies,
                         continue_progress=continue_progress)

@app.route('/api/watchlist/<int:movie_id>/toggle', methods=['POST'])
@login_required
def toggle_watchlist(movie_id):
    """Add or remove movie from watchlist"""
    movie = Movie.query.get_or_404(movie_id)
    
    # Check if already in watchlist
    existing = Watchlist.query.filter_by(
        user_id=current_user.id,
        movie_id=movie_id
    ).first()
    
    if existing:
        # Remove from watchlist
        db.session.delete(existing)
        action = 'removed'
    else:
        # Add to watchlist
        watchlist_item = Watchlist(
            user_id=current_user.id,
            movie_id=movie_id
        )
        db.session.add(watchlist_item)
        action = 'added'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/add_review/<int:movie_id>', methods=['POST'])
@login_required
def add_review(movie_id):
    """Add a review to a movie"""
    movie = Movie.query.get_or_404(movie_id)
    
    rating = request.form.get('rating', type=int)
    comment = request.form.get('comment', '').strip()
    
    # Validate rating
    if not rating or rating < 1 or rating > 5:
        flash('Please provide a valid rating (1-5).', 'danger')
        return redirect(url_for('movie_detail', movie_id=movie_id))
    
    # Check if user already reviewed this movie
    existing_review = Review.query.filter_by(
        user_id=current_user.id,
        movie_id=movie_id
    ).first()
    
    if existing_review:
        # Update existing review
        existing_review.rating = rating
        existing_review.comment = comment
        existing_review.updated_at = datetime.utcnow()
        flash('Review updated successfully!', 'success')
    else:
        # Create new review
        review = Review(
            user_id=current_user.id,
            movie_id=movie_id,
            rating=rating,
            comment=comment
        )
        db.session.add(review)
        flash('Review added successfully!', 'success')
    
    db.session.commit()
    
    return redirect(url_for('movie_detail', movie_id=movie_id))

# ========================================
# ADMIN MOVIE UPLOAD (COMPLETE)
# ========================================

@app.route('/admin/movies/add', methods=['GET', 'POST'])
@login_required
def admin_add_movie():
    """Add new movie with file uploads"""
    # Check if user is admin
    if not getattr(current_user, 'is_admin', False):
        abort(403)
    
    from models import Genre
    
    if request.method == 'GET':
        # GET request - render form
        genres = Genre.query.all()
        return render_template('ADMIN/add_movie.html', 
                             genres=genres,
                             now=datetime.utcnow())
    
    # POST request - process form
    try:
        # Get form data
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        release_year = request.form.get('release_year')
        duration = request.form.get('duration')
        imdb_rating = request.form.get('imdb_rating')
        content_rating = request.form.get('content_rating')
        poster_url_input = request.form.get('poster_url', '').strip()
        trailer_url_input = request.form.get('trailer_url', '').strip()
        is_featured = 'is_featured' in request.form
        download_enabled = 'download_enabled' in request.form
        genre_ids = request.form.getlist('genres')
        
        # Validate required fields
        if not title or not release_year:
            flash('Title and release year are required.', 'danger')
            return redirect(url_for('admin_add_movie'))
        
        # Create movie with basic info
        movie = Movie(
            title=title,
            description=description,
            release_year=int(release_year) if release_year else None,
            duration=int(duration) if duration else None,
            imdb_rating=float(imdb_rating) if imdb_rating else None,
            content_rating=content_rating,
            is_featured=is_featured,
            download_enabled=download_enabled,
            views_count=0,
            download_count=0
        )
        
        # Add genres
        if genre_ids:
            genres = Genre.query.filter(Genre.id.in_(genre_ids)).all()
            if genres:
                movie.genres.extend(genres)
        
        # Save to get ID
        db.session.add(movie)
        db.session.commit()
        
        # Handle file uploads
        uploaded_files = []
        
        # Handle poster upload
        poster_file = request.files.get('poster_file')
        if poster_file and poster_file.filename:
            if allowed_image_file(poster_file.filename):
                try:
                    # Generate secure filename
                    file_ext = poster_file.filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"poster_{movie.id}_{uuid.uuid4().hex}.{file_ext}"
                    filepath = os.path.join(app.config['POSTER_UPLOAD_FOLDER'], unique_filename)
                    
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    
                    # Save the file
                    poster_file.save(filepath)
                    
                    # Verify file was saved
                    if os.path.exists(filepath):
                        # Store relative path for web access
                        movie.poster_url = f"/uploads/posters/{unique_filename}"
                        uploaded_files.append("poster")
                        flash('Poster uploaded successfully!', 'success')
                    else:
                        flash('Poster upload failed - file not saved.', 'warning')
                        
                except Exception as e:
                    current_app.logger.error(f"Poster upload error: {str(e)}")
                    flash('Poster upload failed.', 'warning')
            else:
                flash('Invalid poster file type.', 'warning')
        
        # Handle trailer upload
        trailer_file = request.files.get('trailer_file')
        if trailer_file and trailer_file.filename:
            if allowed_video_file(trailer_file.filename):
                try:
                    file_ext = trailer_file.filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"trailer_{movie.id}_{uuid.uuid4().hex}.{file_ext}"
                    filepath = os.path.join(app.config['TRAILER_UPLOAD_FOLDER'], unique_filename)
                    
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    trailer_file.save(filepath)
                    
                    if os.path.exists(filepath):
                        movie.trailer_url = f"/uploads/trailers/{unique_filename}"
                        uploaded_files.append("trailer")
                        flash('Trailer uploaded successfully!', 'success')
                    else:
                        flash('Trailer upload failed - file not saved.', 'warning')
                        
                except Exception as e:
                    current_app.logger.error(f"Trailer upload error: {str(e)}")
                    flash('Trailer upload failed.', 'warning')
            else:
                flash('Invalid trailer file type.', 'warning')
        
        # Handle movie file upload
        movie_file = request.files.get('movie_file')
        if movie_file and movie_file.filename:
            if allowed_video_file(movie_file.filename):
                try:
                    # Get file extension
                    file_ext = movie_file.filename.rsplit('.', 1)[1].lower()
                    
                    # Create secure filename
                    safe_title = "".join(c for c in movie.title if c.isalnum() or c in (' ', '-', '_')).rstrip()
                    safe_title = safe_title.replace(' ', '_')[:50]
                    unique_filename = f"{safe_title}_{movie.id}_{uuid.uuid4().hex[:8]}.{file_ext}"
                    filepath = os.path.join(app.config['MOVIE_UPLOAD_FOLDER'], unique_filename)
                    
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    
                    # Save the file
                    movie_file.save(filepath)
                    
                    # Verify file was saved
                    if os.path.exists(filepath):
                        file_size = os.path.getsize(filepath)
                        
                        # Save absolute path in database
                        movie.file_path = filepath
                        movie.file_size = file_size
                        movie.file_format = file_ext
                        movie.download_enabled = True
                        
                        uploaded_files.append("movie file")
                        flash(f'Movie file uploaded successfully! Size: {format_file_size(file_size)}', 'success')
                        
                        # Also create a web-accessible symlink
                        try:
                            web_path = os.path.join(app.root_path, 'static', 'uploads', 'movies')
                            os.makedirs(web_path, exist_ok=True)
                            symlink_path = os.path.join(web_path, unique_filename)
                            
                            # Remove existing symlink if it exists
                            if os.path.exists(symlink_path):
                                os.remove(symlink_path)
                            
                            # Create new symlink
                            os.symlink(filepath, symlink_path)
                            
                            # Also store web path for direct access
                            movie.web_file_path = f"/static/uploads/movies/{unique_filename}"
                            
                        except Exception as e:
                            current_app.logger.warning(f"Could not create symlink: {str(e)}")
                            
                    else:
                        flash('Movie file upload failed - file not saved.', 'warning')
                        
                except Exception as e:
                    current_app.logger.error(f"Movie file upload error: {str(e)}")
                    flash(f'Movie file upload failed: {str(e)}', 'warning')
            else:
                allowed_extensions = ', '.join(app.config['ALLOWED_EXTENSIONS'])
                flash(f'Invalid movie file type. Allowed: {allowed_extensions}', 'warning')
        
        # Use provided URLs if no files uploaded
        if not movie.poster_url and poster_url_input:
            movie.poster_url = poster_url_input
        
        if not movie.trailer_url and trailer_url_input:
            movie.trailer_url = trailer_url_input
        
        # Final commit
        db.session.commit()
        
        flash(f'Movie "{title}" added successfully!', 'success')
        
        if uploaded_files:
            flash(f'Uploaded files: {", ".join(uploaded_files)}', 'info')
        
        return redirect(url_for('admin_movies'))
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error adding movie: {str(e)}")
        flash(f'Error adding movie: {str(e)}', 'danger')
        return redirect(url_for('admin_add_movie'))

@app.route('/admin/movies/<int:movie_id>/upload-file', methods=['GET', 'POST'])
@login_required
def admin_upload_movie_file(movie_id):
    """Upload or replace movie file"""
    if not current_user.is_admin:
        abort(403)
    
    movie = Movie.query.get_or_404(movie_id)
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'movie_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['movie_file']
        
        # If user does not select file, browser submits empty file
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_video_file(file.filename):
            try:
                # First, remove existing file if it exists
                if movie.file_path and os.path.exists(movie.file_path):
                    try:
                        os.remove(movie.file_path)
                    except Exception as e:
                        current_app.logger.warning(f"Could not remove old file: {str(e)}")
                
                # Generate secure filename
                filename = secure_filename(file.filename)
                
                # Create unique filename
                safe_title = "".join(c for c in movie.title if c.isalnum() or c in (' ', '-', '_')).rstrip()
                safe_title = safe_title.replace(' ', '_')[:50]
                unique_filename = f"{safe_title}_{movie.id}_{uuid.uuid4().hex[:8]}_{filename}"
                filepath = os.path.join(app.config['MOVIE_UPLOAD_FOLDER'], unique_filename)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                # Save the file
                file.save(filepath)
                
                # Check if file was saved
                if os.path.exists(filepath):
                    file_size = os.path.getsize(filepath)
                    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else None
                    
                    # Update movie record with file info
                    movie.file_path = filepath
                    movie.file_size = file_size
                    movie.file_format = file_ext
                    movie.file_updated = datetime.utcnow()
                    movie.download_enabled = True
                    db.session.commit()
                    
                    # Update symlink
                    try:
                        web_path = os.path.join(app.root_path, 'static', 'uploads', 'movies')
                        os.makedirs(web_path, exist_ok=True)
                        symlink_path = os.path.join(web_path, os.path.basename(filepath))
                        
                        # Remove existing symlink
                        if os.path.exists(symlink_path):
                            os.remove(symlink_path)
                        
                        # Create new symlink
                        os.symlink(filepath, symlink_path)
                        
                        movie.web_file_path = f"/static/uploads/movies/{os.path.basename(filepath)}"
                        db.session.commit()
                        
                    except Exception as e:
                        current_app.logger.warning(f"Could not create symlink: {str(e)}")
                    
                    flash(f'Movie file uploaded successfully! Size: {format_file_size(file_size)}', 'success')
                    return redirect(url_for('movie_detail', movie_id=movie_id))
                else:
                    flash('File upload failed - file not saved.', 'danger')
                    
            except Exception as e:
                flash(f'Error uploading file: {str(e)}', 'danger')
                current_app.logger.error(f"File upload error: {str(e)}")
        else:
            allowed_extensions = ', '.join(app.config['ALLOWED_EXTENSIONS'])
            flash(f'Invalid file type. Allowed types: {allowed_extensions}', 'danger')
    
    # GET request - render form
    return render_template('ADMIN/upload_file.html', 
                         movie=movie,
                         upload_folder=app.config['MOVIE_UPLOAD_FOLDER'],
                         allowed_extensions=', '.join(app.config['ALLOWED_EXTENSIONS']))

@app.route('/admin/movies/<int:movie_id>/delete-file', methods=['POST'])
@login_required
def admin_delete_movie_file(movie_id):
    """Delete movie file"""
    if not current_user.is_admin:
        abort(403)
    
    movie = Movie.query.get_or_404(movie_id)
    
    try:
        if movie.file_path and os.path.exists(movie.file_path):
            # Delete the file
            os.remove(movie.file_path)
            
            # Delete symlink if exists
            if movie.web_file_path:
                symlink_path = os.path.join(app.root_path, movie.web_file_path.lstrip('/'))
                if os.path.exists(symlink_path):
                    os.remove(symlink_path)
            
            # Update movie record
            movie.file_path = None
            movie.file_size = None
            movie.file_format = None
            movie.web_file_path = None
            movie.file_updated = datetime.utcnow()
            movie.download_enabled = False
            
            db.session.commit()
            
            flash('Movie file deleted successfully!', 'success')
        else:
            flash('No movie file found.', 'warning')
            
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('admin_edit_movie', movie_id=movie_id))

# ========================================
# MOVIE STREAMING ROUTES
# ========================================

@app.route('/api/movie/<int:movie_id>/watchtime', methods=['POST'])
@login_required
def update_watch_time(movie_id):
    """Update watch time for continue watching"""
    data = request.json
    current_time = data.get('current_time', 0)
    duration = data.get('duration', 0)
    
    # Get current profile
    current_profile = Profile.query.filter_by(user_id=current_user.id, is_active=True).first()
    
    if not current_profile:
        return jsonify({'success': False, 'error': 'No active profile'})
    
    # Update or create continue watching entry
    continue_watching = ContinueWatching.query.filter_by(
        profile_id=current_profile.id,
        movie_id=movie_id
    ).first()
    
    if continue_watching:
        continue_watching.current_time = current_time
        continue_watching.duration = duration
        continue_watching.updated_at = datetime.utcnow()
    else:
        continue_watching = ContinueWatching(
            profile_id=current_profile.id,
            movie_id=movie_id,
            current_time=current_time,
            duration=duration
        )
        db.session.add(continue_watching)
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/serve-movie-stream/<int:movie_id>')
@login_required
def serve_movie_stream(movie_id):
    """Serve movie file for streaming with proper headers"""
    movie = Movie.query.get_or_404(movie_id)
    
    if not movie.file_path or not os.path.exists(movie.file_path):
        abort(404, "Movie file not found")
    
    # Determine MIME type based on file extension
    mime_type = 'video/mp4'
    if movie.file_path.endswith('.webm'):
        mime_type = 'video/webm'
    elif movie.file_path.endswith('.mkv'):
        mime_type = 'video/x-matroska'
    elif movie.file_path.endswith('.avi'):
        mime_type = 'video/x-msvideo'
    
    # Enable range requests for streaming
    range_header = request.headers.get('Range', None)
    file_size = os.path.getsize(movie.file_path)
    
    if range_header:
        # Parse range header
        byte1, byte2 = 0, None
        match = re.search(r'(\d+)-(\d*)', range_header)
        if match:
            groups = match.groups()
            if groups[0]:
                byte1 = int(groups[0])
            if groups[1]:
                byte2 = int(groups[1])
        
        length = file_size - byte1
        if byte2 is not None:
            length = byte2 - byte1 + 1
        
        # Create partial response
        data = None
        with open(movie.file_path, 'rb') as f:
            f.seek(byte1)
            data = f.read(length)
        
        rv = Response(data, 
                     206,  # Partial Content
                     mimetype=mime_type,
                     direct_passthrough=True)
        rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
        rv.headers.add('Accept-Ranges', 'bytes')
        rv.headers.add('Content-Length', str(length))
        return rv
    else:
        # Full file response
        return send_file(
            movie.file_path,
            mimetype=mime_type,
            as_attachment=False,
            conditional=True
        )

@app.route('/serve-subtitle/<int:movie_id>')
@login_required
def serve_subtitle(movie_id):
    """Serve subtitle file if available"""
    movie = Movie.query.get_or_404(movie_id)
    
    if not movie.subtitle_path or not os.path.exists(movie.subtitle_path):
        abort(404, "Subtitle file not found")
    
    return send_file(
        movie.subtitle_path,
        mimetype='text/vtt',
        as_attachment=False
    )

@app.route('/download/movie/<token>')
@login_required
def download_movie_file(token):
    """Serve the actual movie file for download"""
    
    # -----------------------------
    # Validate token
    # -----------------------------
    token_data = verify_download_token(token, serializer)
    if not token_data:
        flash('Download link has expired or is invalid.', 'danger')
        return redirect(url_for('movies_index'))

    # Token must belong to logged-in user
    if token_data['user_id'] != current_user.id:
        abort(403)

    movie_id = token_data['movie_id']
    movie = Movie.query.get_or_404(movie_id)

    if not movie.download_enabled:
        flash('Download is not available for this movie.', 'warning')
        return redirect(url_for('movie_detail', movie_id=movie_id))

    # Find download record
    download_record = MovieDownload.query.filter_by(
        download_token=token,
        user_id=current_user.id,
        movie_id=movie_id
    ).first()

    try:
        # -----------------------------
        # SERVE THE ACTUAL VIDEO FILE
        # -----------------------------
        # Use the file path from your debug output
        video_path = movie.file_path
        
        # Verify the file exists
        if not video_path or not os.path.exists(video_path):
            flash(f'Video file not found at: {video_path}', 'danger')
            return redirect(url_for('movie_detail', movie_id=movie_id))
        
        # Get file info
        file_size = os.path.getsize(video_path)
        filename = os.path.basename(video_path)
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Set MIME type based on file extension
        mime_types = {
            '.mp4': 'video/mp4',
            '.mkv': 'video/x-matroska',
            '.avi': 'video/x-msvideo',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.flv': 'video/x-flv',
            '.webm': 'video/webm',
        }
        mime = mime_types.get(file_ext, 'video/mp4')
        
        # Create a clean download filename
        safe_title = re.sub(r'[^\w\s-]', '', movie.title)  # Remove special characters
        safe_title = safe_title.replace(' ', '_')
        download_filename = f"{safe_title}_{movie.release_year}{file_ext}"
        
        # Update download record
        if download_record:
            download_record.status = 'downloading'
            download_record.started_at = datetime.utcnow()
            download_record.file_size = file_size
            download_record.file_path = video_path
            db.session.commit()
        
        response = send_file(
            video_path,
            as_attachment=True,  
            download_name=download_filename, 
            mimetype=mime,  
            conditional=True  
        )
        
        # Add headers for better download experience
        response.headers['Content-Length'] = file_size
        response.headers['Accept-Ranges'] = 'bytes'
        
        # Mark download as completed
        if download_record:
            download_record.status = 'completed'
            download_record.completed_at = datetime.utcnow()
            db.session.commit()
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Download failed: {str(e)}")
        
        # Update download record on failure
        if download_record:
            download_record.status = 'failed'
            download_record.error_message = str(e)
            download_record.failed_at = datetime.utcnow()
            db.session.commit()
        
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('movie_detail', movie_id=movie_id))
    
# ========================================
# MOVIE ROUTES (UPDATED)
# ========================================

@app.route('/movies')
def movies_index():
    """Main movies listing page"""
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = 12
    genre_id = request.args.get('genre', type=int)
    year = request.args.get('year', type=int)
    sort = request.args.get('sort', 'newest')
    
    # Build query
    query = Movie.query
    
    # Apply filters
    if genre_id:
        query = query.join(Movie.genres).filter(Genre.id == genre_id)
    
    if year:
        query = query.filter(Movie.release_year == year)
    
    # Apply sorting
    if sort == 'newest':
        query = query.order_by(Movie.release_year.desc(), Movie.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Movie.release_year.asc(), Movie.created_at.asc())
    elif sort == 'rating':
        # This would require a subquery for average rating
        query = query.order_by(Movie.imdb_rating.desc() if Movie.imdb_rating else Movie.created_at.desc())
    elif sort == 'views':
        query = query.order_by(Movie.views_count.desc())
    elif sort == 'downloads':
        query = query.order_by(Movie.download_count.desc())
    else:
        query = query.order_by(Movie.created_at.desc())
    
    # Paginate
    movies = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get genres for filter
    genres = Genre.query.all()
    
    # Get unique years for filter
    years = db.session.query(Movie.release_year).distinct().order_by(Movie.release_year.desc()).all()
    years = [y[0] for y in years if y[0]]
    
    return render_template('MOVIES/index.html', 
                         movies=movies.items,
                         pagination=movies,
                         genres=genres,
                         years=years,
                         selected_genre=genre_id,
                         selected_year=year,
                         selected_sort=sort)

# ========================================
# SEARCH ROUTE
# ========================================

@app.route('/search')
def search():
    """Search movies with filters"""
    # Get search parameters
    query = request.args.get('q', '').strip()
    genre_id = request.args.get('genre', type=int)
    year = request.args.get('year', type=int)
    sort = request.args.get('sort', '')
    
    # Build base query
    if query:
        # Search in title and description
        search_filter = Movie.title.ilike(f'%{query}%') | Movie.description.ilike(f'%{query}%')
        movies_query = Movie.query.filter(search_filter)
    else:
        movies_query = Movie.query
    
    # Apply genre filter
    if genre_id:
        movies_query = movies_query.join(Movie.genres).filter(Genre.id == genre_id)
    
    # Apply year filter
    if year:
        movies_query = movies_query.filter(Movie.release_year == year)
    
    # Apply sorting
    if sort == 'newest':
        movies_query = movies_query.order_by(Movie.release_year.desc(), Movie.created_at.desc())
    elif sort == 'oldest':
        movies_query = movies_query.order_by(Movie.release_year.asc(), Movie.created_at.asc())
    elif sort == 'rating':
        movies_query = movies_query.order_by(Movie.imdb_rating.desc())
    elif sort == 'views':
        movies_query = movies_query.order_by(Movie.views_count.desc())
    elif sort == 'trending':
        # Trending: combination of recent views and rating
        movies_query = movies_query.order_by(
            Movie.views_count.desc(),
            Movie.imdb_rating.desc()
        )
    else:
        # Default: sort by relevance (if query) or newest
        if query:
            movies_query = movies_query.order_by(Movie.views_count.desc())
        else:
            movies_query = movies_query.order_by(Movie.created_at.desc())
    
    # Execute query
    movies = movies_query.all()
    
    # Get all genres for filter dropdown
    genres = Genre.query.all()
    
    # Get unique years for filter dropdown
    years = db.session.query(Movie.release_year)\
        .distinct()\
        .order_by(Movie.release_year.desc())\
        .all()
    years = [y[0] for y in years if y[0]]
    
    return render_template('MOVIES/search.html',
                         movies=movies,
                         genres=genres,
                         years=years,
                         query=query,
                         selected_genre=genre_id,
                         selected_year=year,
                         selected_sort=sort)

# ========================================
# USER DOWNLOAD MANAGEMENT
# ========================================

@app.route('/downloads')
@login_required
def user_downloads():
    """Show user's download history"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    downloads = MovieDownload.query.filter_by(user_id=current_user.id)\
                                   .order_by(MovieDownload.created_at.desc())\
                                   .paginate(page=page, per_page=per_page, error_out=False)
    
    # Calculate stats
    total_downloads = MovieDownload.query.filter_by(user_id=current_user.id).count()
    completed_downloads = MovieDownload.query.filter_by(user_id=current_user.id, status='completed').count()
    total_size = db.session.query(db.func.sum(MovieDownload.file_size)).filter_by(
        user_id=current_user.id, status='completed'
    ).scalar() or 0
    
    # Check download limits
    from utils.download_utils import check_download_limits
    limits = check_download_limits(current_user.id)
    
    return render_template('USER/downloads.html', 
                         downloads=downloads.items,
                         pagination=downloads,
                         total_downloads=total_downloads,
                         completed_downloads=completed_downloads,
                         total_size=total_size,
                         limits=limits)

@app.route('/api/downloads/clear', methods=['DELETE'])
@login_required
def clear_downloads():
    """Clear user's download history"""
    try:
        MovieDownload.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Download history cleared successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/downloads/<int:download_id>', methods=['DELETE'])
@login_required
def delete_download(download_id):
    """Delete a specific download record"""
    download = MovieDownload.query.get_or_404(download_id)
    
    # Check ownership
    if download.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        db.session.delete(download)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Download record deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ========================================
# ADMIN MOVIE UPLOAD
# ========================================

@app.route('/admin/movie/<int:movie_id>/upload', methods=['GET', 'POST'])
@login_required
def upload_movie_file(movie_id):
    """Admin route to upload actual movie files"""
    if not current_user.is_admin:
        abort(403)
    
    movie = Movie.query.get_or_404(movie_id)
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'movie_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['movie_file']
        
        # If user does not select file, browser submits empty file
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
            try:
                # Generate secure filename
                filename = secure_filename(file.filename)
                # Add timestamp and UUID to avoid conflicts
                unique_filename = f"{movie_id}_{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['MOVIE_UPLOAD_FOLDER'], unique_filename)
                
                # Save the file
                file.save(filepath)
                
                # Update movie record with file info
                movie.file_path = filepath
                movie.file_size = os.path.getsize(filepath)
                movie.file_format = filename.rsplit('.', 1)[1].lower() if '.' in filename else None
                movie.file_updated = datetime.utcnow()
                movie.download_enabled = True
                db.session.commit()
                
                flash('Movie file uploaded successfully!', 'success')
                return redirect(url_for('movie_detail', movie_id=movie_id))
                
            except Exception as e:
                flash(f'Error uploading file: {str(e)}', 'danger')
                return redirect(request.url)
        else:
            allowed_extensions = ', '.join(app.config['ALLOWED_EXTENSIONS'])
            flash(f'Invalid file type. Allowed types: {allowed_extensions}', 'danger')
    
    return render_template('ADMIN/upload_movie.html', movie=movie)

# ========================================
# UPDATE EXISTING AUTH ROUTES FOR DOWNLOAD
# ========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.is_active:
                login_user(user)
                
                # Check if there's a movie waiting for download
                download_movie_id = session.get('download_movie_id')
                if download_movie_id:
                    session.pop('download_movie_id', None)
                    return redirect(url_for('prepare_download', movie_id=download_movie_id))
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Account not activated. Please verify your email.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('AUTH/login.html')

@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('info/terms.html')

@app.route('/privacy')
def privacy():
    """Privacy Policy page"""
    return render_template('info/privacy.html')

@app.route('/faq')
def faq():
    """FAQ page"""
    return render_template('info/faq.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('info/contact.html')

@app.route('/help')
def help():
    """Help/FAQ page"""
    return render_template('info/help.html')

@app.route('/cookies')
def cookies():
    """Cookies Policy page"""
    return render_template('info/cookies.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum file size is 4GB.', 'danger')
    return redirect(request.referrer or url_for('movies_index'))

# ========================================
# ADMIN MOVIE MANAGEMENT ROUTES
# ========================================

@app.route('/admin/movies')
@login_required
def admin_movies():
    """Admin movie management dashboard"""
    if not current_user.is_admin:
        abort(403)
    
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'newest')
    
    # Build query
    query = Movie.query
    
    # Apply search
    if search:
        query = query.filter(
            Movie.title.ilike(f'%{search}%') | 
            Movie.description.ilike(f'%{search}%')
        )
    
    # Apply sorting
    if sort == 'newest':
        query = query.order_by(Movie.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Movie.created_at.asc())
    elif sort == 'title_asc':
        query = query.order_by(Movie.title.asc())
    elif sort == 'title_desc':
        query = query.order_by(Movie.title.desc())
    elif sort == 'views':
        query = query.order_by(Movie.views_count.desc())
    elif sort == 'downloads':
        query = query.order_by(Movie.download_count.desc())
    
    # Paginate
    movies = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('ADMIN/movies.html',
                         movies=movies.items,
                         pagination=movies,
                         search=search,
                         sort=sort)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    # Security check
    if '..' in filename or filename.startswith('/'):
        abort(404)
    
    # Determine folder based on path
    if filename.startswith('posters/'):
        folder = app.config['POSTER_UPLOAD_FOLDER']
        # Remove the 'posters/' prefix from filename
        actual_filename = filename.replace('posters/', '', 1)
    elif filename.startswith('trailers/'):
        folder = app.config['TRAILER_UPLOAD_FOLDER']
        actual_filename = filename.replace('trailers/', '', 1)
    elif filename.startswith('movies/'):
        folder = app.config['MOVIE_UPLOAD_FOLDER']
        actual_filename = filename.replace('movies/', '', 1)
    else:
        # Default to posters folder for backward compatibility
        folder = app.config['POSTER_UPLOAD_FOLDER']
        actual_filename = filename
    
    filepath = os.path.join(folder, actual_filename)
    
    if not os.path.exists(filepath):
        # Try direct path in all folders
        for folder_type in ['POSTER_UPLOAD_FOLDER', 'TRAILER_UPLOAD_FOLDER', 'MOVIE_UPLOAD_FOLDER']:
            test_path = os.path.join(app.config[folder_type], filename)
            if os.path.exists(test_path):
                filepath = test_path
                break
        else:
            abort(404)
    
    # Determine MIME type
    mime_type = 'application/octet-stream'
    if filepath.lower().endswith('.png'):
        mime_type = 'image/png'
    elif filepath.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif filepath.lower().endswith('.gif'):
        mime_type = 'image/gif'
    elif filepath.lower().endswith('.webp'):
        mime_type = 'image/webp'
    elif filepath.lower().endswith('.mp4'):
        mime_type = 'video/mp4'
    elif filepath.lower().endswith('.mkv'):
        mime_type = 'video/x-matroska'
    elif filepath.lower().endswith('.avi'):
        mime_type = 'video/x-msvideo'
    elif filepath.lower().endswith('.mov'):
        mime_type = 'video/quicktime'
    elif filepath.lower().endswith('.txt'):
        mime_type = 'text/plain'
    
    return send_file(filepath, mimetype=mime_type)

# Add a direct route for movie files
@app.route('/movie-files/<filename>')
@login_required
def serve_movie_file(filename):
    """Serve movie files directly (for streaming)"""
    # Security check
    if '..' in filename or filename.startswith('/'):
        abort(404)
    
    filepath = os.path.join(app.config['MOVIE_UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        abort(404)
    
    # Get MIME type
    mime_type = get_mime_type(os.path.splitext(filename)[1])
    
    # Enable range requests for streaming
    range_header = request.headers.get('Range', None)
    file_size = os.path.getsize(filepath)
    
    if range_header:
        # Parse range header
        byte1, byte2 = 0, None
        match = re.search(r'(\d+)-(\d*)', range_header)
        if match:
            groups = match.groups()
            if groups[0]:
                byte1 = int(groups[0])
            if groups[1]:
                byte2 = int(groups[1])
        
        length = file_size - byte1
        if byte2 is not None:
            length = byte2 - byte1 + 1
        
        # Create partial response
        data = None
        with open(filepath, 'rb') as f:
            f.seek(byte1)
            data = f.read(length)
        
        rv = Response(data, 
                     206,  # Partial Content
                     mimetype=mime_type,
                     direct_passthrough=True)
        rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
        rv.headers.add('Accept-Ranges', 'bytes')
        rv.headers.add('Content-Length', str(length))
        return rv
    else:
        # Full file response
        return send_file(
            filepath,
            mimetype=mime_type,
            as_attachment=False,
            conditional=True
        )

@app.route('/admin/movies/<int:movie_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_movie(movie_id):
    """Edit existing movie"""
    if not current_user.is_admin:
        abort(403)
    
    from models import Genre
    
    movie = Movie.query.get_or_404(movie_id)
    
    if request.method == 'POST':
        try:
            # Update movie data
            movie.title = request.form.get('title')
            movie.description = request.form.get('description')
            movie.release_year = request.form.get('release_year')
            movie.duration = request.form.get('duration')
            movie.imdb_rating = request.form.get('imdb_rating')
            movie.content_rating = request.form.get('content_rating')
            movie.poster_url = request.form.get('poster_url')
            movie.trailer_url = request.form.get('trailer_url')
            movie.is_featured = 'is_featured' in request.form
            movie.download_enabled = 'download_enabled' in request.form
            
            # Handle release year conversion
            if movie.release_year:
                movie.release_year = int(movie.release_year)
            
            # Handle duration conversion
            if movie.duration:
                movie.duration = int(movie.duration)
            
            # Handle rating conversion
            if movie.imdb_rating:
                movie.imdb_rating = float(movie.imdb_rating)
            
            # Update genres
            genre_ids = request.form.getlist('genres')
            movie.genres.clear()
            if genre_ids:
                genres = Genre.query.filter(Genre.id.in_(genre_ids)).all()
                movie.genres.extend(genres)
            
            db.session.commit()
            
            flash(f'Movie "{movie.title}" updated successfully!', 'success')
            return redirect(url_for('admin_movies'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating movie: {str(e)}', 'danger')
            return redirect(request.url)
    
    # GET request - render form with current data
    genres = Genre.query.all()
    selected_genre_ids = [genre.id for genre in movie.genres]
    
    return render_template('ADMIN/movie_form.html',
                         movie=movie,
                         genres=genres,
                         selected_genre_ids=selected_genre_ids,
                         action='Edit')

@app.route('/admin/movies/<int:movie_id>/delete', methods=['POST'])
@login_required
def admin_delete_movie(movie_id):
    """Delete movie"""
    if not current_user.is_admin:
        abort(403)
    
    movie = Movie.query.get_or_404(movie_id)
    
    try:
        movie_title = movie.title
        
        # Delete associated records first
        Review.query.filter_by(movie_id=movie_id).delete()
        Watchlist.query.filter_by(movie_id=movie_id).delete()
        ContinueWatching.query.filter_by(movie_id=movie_id).delete()
        MovieDownload.query.filter_by(movie_id=movie_id).delete()
        
        # Delete the movie file if exists
        if movie.file_path and os.path.exists(movie.file_path):
            try:
                os.remove(movie.file_path)
            except Exception:
                pass
        
        # Delete the movie
        db.session.delete(movie)
        db.session.commit()
        
        flash(f'Movie "{movie_title}" deleted successfully!', 'success')
        return jsonify({'success': True, 'message': 'Movie deleted'})
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting movie: {str(e)}', 'danger')
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/api/download/status/<int:download_id>')
@login_required
def download_status(download_id):
    """Check download status (for AJAX polling)"""
    download = MovieDownload.query.get_or_404(download_id)
    
    # Check ownership
    if download.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Check if file exists
    file_exists = False
    file_size = download.file_size or 0
    
    if download.movie and download.movie.file_path:
        file_exists = os.path.exists(download.movie.file_path)
        if file_exists and not file_size:
            file_size = os.path.getsize(download.movie.file_path)
    
    return jsonify({
        'id': download.id,
        'status': download.status,
        'movie_id': download.movie_id,
        'movie_title': download.movie.title if download.movie else 'Unknown',
        'file_exists': file_exists,
        'file_size': file_size,
        'file_size_formatted': format_file_size(file_size),
        'created_at': download.created_at.isoformat() if download.created_at else None,
        'started_at': download.started_at.isoformat() if download.started_at else None,
        'completed_at': download.completed_at.isoformat() if download.completed_at else None,
        'failed_at': download.failed_at.isoformat() if download.failed_at else None,
        'error_message': download.error_message
    })

@app.route('/api/download/progress/<token>')
@login_required
def download_progress(token):
    """Simulate download progress (for demo purposes)"""
    download = MovieDownload.query.filter_by(download_token=token).first()
    
    if not download or download.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Simulate progress based on status
    if download.status == 'completed':
        return jsonify({
            'progress': 100,
            'downloaded': download.file_size or 1000000000,
            'total': download.file_size or 1000000000,
            'speed': 50,
            'estimated': 0,
            'status': 'completed'
        })
    elif download.status == 'failed':
        return jsonify({
            'progress': 0,
            'downloaded': 0,
            'total': 1,
            'speed': 0,
            'estimated': 0,
            'status': 'failed',
            'error': download.error_message
        })
    elif download.status == 'downloading' and download.started_at:
        # Simulate progress based on time
        elapsed = (datetime.utcnow() - download.started_at).total_seconds()
        
        # Simulate 50MB/s download speed
        total_size = download.file_size or 1000000000
        downloaded = min(total_size, int(elapsed * 50 * 1024 * 1024))
        progress = min(100, (downloaded / total_size) * 100)
        
        # Calculate remaining time
        remaining = max(0, (total_size - downloaded) / (50 * 1024 * 1024))
        
        return jsonify({
            'progress': round(progress, 1),
            'downloaded': downloaded,
            'total': total_size,
            'speed': 50,
            'estimated': remaining,
            'status': 'downloading'
        })
    
    return jsonify({
        'progress': 0,
        'downloaded': 0,
        'total': 1,
        'speed': 0,
        'estimated': 0,
        'status': download.status
    })

@app.route('/admin/movies/bulk-actions', methods=['POST'])
@login_required
def admin_bulk_movie_actions():
    """Handle bulk movie actions"""
    if not current_user.is_admin:
        abort(403)
    
    data = request.json
    action = data.get('action')
    movie_ids = data.get('movie_ids', [])
    
    if not movie_ids:
        return jsonify({'success': False, 'error': 'No movies selected'})
    
    try:
        if action == 'delete':
            # Delete movies and their associated data
            for movie_id in movie_ids:
                movie = Movie.query.get(movie_id)
                if movie:
                    # Delete associated records
                    Review.query.filter_by(movie_id=movie_id).delete()
                    Watchlist.query.filter_by(movie_id=movie_id).delete()
                    ContinueWatching.query.filter_by(movie_id=movie_id).delete()
                    MovieDownload.query.filter_by(movie_id=movie_id).delete()
                    
                    # Delete movie file if exists
                    if movie.file_path and os.path.exists(movie.file_path):
                        try:
                            os.remove(movie.file_path)
                        except:
                            pass
                    
                    db.session.delete(movie)
            
            db.session.commit()
            return jsonify({'success': True, 'message': f'{len(movie_ids)} movies deleted'})
            
        elif action == 'feature':
            # Toggle featured status
            Movie.query.filter(Movie.id.in_(movie_ids)).update(
                {'is_featured': True}, 
                synchronize_session=False
            )
            db.session.commit()
            return jsonify({'success': True, 'message': f'{len(movie_ids)} movies featured'})
            
        elif action == 'unfeature':
            # Toggle featured status
            Movie.query.filter(Movie.id.in_(movie_ids)).update(
                {'is_featured': False}, 
                synchronize_session=False
            )
            db.session.commit()
            return jsonify({'success': True, 'message': f'{len(movie_ids)} movies unfeatured'})
            
        elif action == 'enable_download':
            # Enable downloads
            Movie.query.filter(Movie.id.in_(movie_ids)).update(
                {'download_enabled': True}, 
                synchronize_session=False
            )
            db.session.commit()
            return jsonify({'success': True, 'message': f'{len(movie_ids)} downloads enabled'})
            
        elif action == 'disable_download':
            # Disable downloads
            Movie.query.filter(Movie.id.in_(movie_ids)).update(
                {'download_enabled': False}, 
                synchronize_session=False
            )
            db.session.commit()
            return jsonify({'success': True, 'message': f'{len(movie_ids)} downloads disabled'})
            
        else:
            return jsonify({'success': False, 'error': 'Invalid action'})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    
# ========================================
# MOVIE DOWNLOAD ROUTES (COMPLETE FIX)
# ========================================

@app.route('/movie/<int:movie_id>/download')
@login_required
def request_movie_download(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if not movie.download_enabled:
        flash('Downloading is not available for this movie.', 'warning')
        return redirect(url_for('movie_detail', movie_id=movie_id))

    # Check for recent completed download
    recent_download = MovieDownload.query.filter_by(
        movie_id=movie_id,
        user_id=current_user.id,
        status='completed'
    ).order_by(MovieDownload.created_at.desc()).first()

    if recent_download:
        # Validate that the old token is still valid
        token_data = verify_download_token(recent_download.download_token, serializer)

        if token_data:
            flash('You recently downloaded this movie. Reusing existing download link.', 'info')
            return redirect(url_for('download_movie_file',
                                    token=recent_download.download_token))
        else:
            # Old token expired → create a new one
            flash('Your previous download link expired. Generating a new one.', 'info')

    # No recent download OR expired token → prepare a new download
    return redirect(url_for('prepare_download', movie_id=movie_id))

@app.route('/movie/<int:movie_id>/download/prepare')
@login_required
def prepare_download(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if not movie.download_enabled:
        flash('Download is not allowed for this movie.', 'warning')
        return redirect(url_for('movie_detail', movie_id=movie_id))

    # Check download limits
    limits = check_download_limits(current_user.id)
    if not limits['allowed']:
        flash(limits['message'], 'danger')
        return redirect(url_for('movie_detail', movie_id=movie_id))

    # Generate download token
    download_token = generate_download_token(movie_id, current_user.id, serializer)

    # Create download record
    download_record = MovieDownload(
        movie_id=movie_id,
        user_id=current_user.id,
        download_token=download_token,
        status='pending',
        created_at=datetime.utcnow()
    )
    db.session.add(download_record)
    db.session.commit()

    # IMPORTANT FIX: remove _external=True
    return redirect(url_for('download_movie_file', token=download_token))


def find_movie_file(movie):
    """Find movie file in multiple possible locations"""
    if not movie.file_path:
        return None
    
    # Try the stored path first
    if os.path.exists(movie.file_path):
        return movie.file_path
    
    # Try in upload folder
    upload_path = os.path.join(app.config['MOVIE_UPLOAD_FOLDER'], os.path.basename(movie.file_path))
    if os.path.exists(upload_path):
        return upload_path
    
    # Try relative path from instance
    instance_path = os.path.join(app.instance_path, os.path.basename(movie.file_path))
    if os.path.exists(instance_path):
        return instance_path
    
    # Try relative path from project root
    root_path = os.path.join(app.root_path, '..', movie.file_path)
    if os.path.exists(root_path):
        return root_path
    
    return None

def get_mime_type(file_ext):
    """Get MIME type from file extension"""
    mime_types = {
        '.mp4': 'video/mp4',
        '.mkv': 'video/x-matroska',
        '.avi': 'video/x-msvideo',
        '.mov': 'video/quicktime',
        '.wmv': 'video/x-ms-wmv',
        '.flv': 'video/x-flv',
        '.webm': 'video/webm',
        '.txt': 'text/plain',
        '.pdf': 'application/pdf',
    }
    return mime_types.get(file_ext.lower(), 'application/octet-stream')

@app.route('/debug/movie/<int:movie_id>')
def debug_movie(movie_id):
    """Debug endpoint to check movie data"""
    movie = Movie.query.get_or_404(movie_id)
    return jsonify({
        'id': movie.id,
        'title': movie.title,
        'poster_url': movie.poster_url,
        'has_poster': bool(movie.poster_url),
        'poster_exists': os.path.exists(movie.poster_url.replace('/uploads/posters/', app.config['POSTER_UPLOAD_FOLDER'] + '/')) if movie.poster_url else False
    })

@app.route('/test-oauth')
def test_oauth():
    return f'''
    <h1>Test OAuth Links</h1>
    <p>Google login redirect: <a href="{url_for('oauth.google_login_redirect')}">Click here</a></p>
    <p>Direct Google OAuth: <a href="{url_for('google.login')}">Direct link</a></p>
    <p>Both should redirect to the same place.</p>
    '''

@app.route('/test-oauth-links')
def test_oauth_links():
    links = {
        'oauth_redirect': url_for('oauth.google_login_redirect'),
        'direct_google_login': url_for('google.login'),
        'google_authorized': url_for('google.authorized') if 'google.authorized' in app.view_functions else 'Not found'
    }
    return jsonify(links)

# Change this:
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(
        debug=True,
        port=5000,
        host='0.0.0.0'
    )