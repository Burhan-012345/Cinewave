from flask import render_template, current_app
from flask_mail import Message

def send_otp_email(email, otp, app=None):
    """Send OTP email for registration"""
    try:
        print(f"\n{'='*60}")
        print(f"ATTEMPTING TO SEND OTP TO: {email}")
        print(f"OTP CODE: {otp}")
        print(f"USING MAIL CONFIG:")
        print(f"  MAIL_SERVER: {current_app.config.get('MAIL_SERVER')}")
        print(f"  MAIL_PORT: {current_app.config.get('MAIL_PORT')}")
        print(f"  MAIL_USERNAME: {current_app.config.get('MAIL_USERNAME')}")
        print(f"  MAIL_USE_TLS: {current_app.config.get('MAIL_USE_TLS')}")
        print(f"{'='*60}\n")
        
        # Use the app's mail instance (already initialized in app.py)
        from flask_mail import Mail
        mail = Mail(current_app)
        
        msg = Message(
            subject='Your CineWave Verification Code',
            sender=current_app.config.get('MAIL_DEFAULT_SENDER', 'fiscalflow.service@gmail.com'),
            recipients=[email]
        )
        
        # Add both HTML and plain text
        msg.html = render_template('email/otp_email.html', 
                                 otp=otp, 
                                 site_url=current_app.config.get('SITE_URL', 'http://localhost:5000'))
        
        msg.body = f"""Your CineWave Verification Code: {otp}
        
This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
The CineWave Team
        """
        
        # Send the email
        mail.send(msg)
        print(f"✅ OTP email sent successfully to {email}")
        return True
        
    except Exception as e:
        print(f"❌ FAILED to send OTP email to {email}")
        print(f"   Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # For development/testing, print the OTP
        print(f"\n📧 DEVELOPMENT MODE: OTP for {email} is: {otp}")
        print("   Check console for OTP if email fails.")
        return True  # Return True for development to continue flow

def send_reset_link_email(email, reset_link, app=None):
    """Send password reset link email"""
    # Use current_app if no app is provided
    if app is None:
        app = current_app
    
    try:
        print(f"\n{'='*60}")
        print(f"ATTEMPTING TO SEND RESET LINK TO: {email}")
        print(f"RESET LINK: {reset_link}")
        print(f"{'='*60}\n")
        
        with app.app_context():
            from flask_mail import Mail
            mail = Mail(current_app)  # Create mail instance with current app
            
            msg = Message(
                subject='Reset Your CineWave Password',
                sender=app.config.get('MAIL_DEFAULT_SENDER', 'fiscalflow.service@gmail.com'),
                recipients=[email]
            )
            
            msg.html = render_template('email/reset_link_email.html', 
                                     reset_link=reset_link)
            
            msg.body = f"""Reset Your CineWave Password
            
Click this link to reset your password: {reset_link}

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email.

Best regards,
The CineWave Team
            """
            
            mail.send(msg)
            print(f"✅ Reset email sent successfully to {email}")
            return True
            
    except Exception as e:
        print(f"❌ FAILED to send reset email to {email}")
        print(f"   Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
def send_download_confirmation(user_email, user_name, movie_title, download_url, 
                               movie_poster=None, release_year=None, duration=None, 
                               file_size=None, format=None, download_count=None,
                               expiry_days=30, app=None):
    """Send download confirmation email"""
    
    # Use current_app if no app is provided
    if app is None:
        app = current_app
    
    try:
        with app.app_context():
            from flask_mail import Mail
            mail = Mail(current_app)  # Create mail instance with current app
            
            msg = Message(
                subject=f'Your "{movie_title}" Download is Ready!',
                sender=app.config.get('MAIL_DEFAULT_SENDER', 'fiscalflow.service@gmail.com'),
                recipients=[user_email]
            )
            
            # Simplified for testing
            msg.body = f"""CineWave - Your Movie Download is Ready!

Hi {user_name},

Your download of "{movie_title}" is ready.

Download Link: {download_url}

This link will expire in {expiry_days} days.

Best regards,
The CineWave Team
            """
            
            mail.send(msg)
            print(f"✅ Download confirmation sent to {user_email}")
            return True
            
    except Exception as e:
        print(f"❌ Failed to send download confirmation: {str(e)}")
        return False