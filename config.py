import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(basedir, 'instance', 'cinewave.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_SECURE = False 
    SESSION_COOKIE_HTTPONLY = True

    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'fiscalflow.service@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'pgoc apte zjyy wogn'
    MAIL_DEFAULT_SENDER = ('CineWave', 'fiscalflow.service@gmail.com')

    GOOGLE_OAUTH_CLIENT_ID = os.environ.get('GOOGLE_OAUTH_CLIENT_ID') or '533335355559-qogth6bckuo289o15fs321bfaj04q096.apps.googleusercontent.com'
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET') or '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'

    OAUTHLIB_INSECURE_TRANSPORT = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '1')  
    OAUTHLIB_RELAX_TOKEN_SCOPE = os.environ.get('OAUTHLIB_RELAX_TOKEN_SCOPE', '1')

    OTP_EXPIRY_MINUTES = 10
    RESET_TOKEN_EXPIRY_MINUTES = 10

    PASSWORD_HISTORY_COUNT = 5

    MAX_CONTENT_LENGTH = 4 * 1024 * 1024 * 1024  