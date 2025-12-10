from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

from .user import User
from .profile import Profile
from .movie import Movie
from .genre import Genre
from .review import Review
from .watchlist import Watchlist
from .continue_watching import ContinueWatching
from .password_history import PasswordHistory
from .reset_token import ResetToken
from .movie_download import MovieDownload

from .oauth_models import OAuth


__all__ = [
    'db',
    'User',
    'Profile',
    'Movie',
    'Genre',
    'Review',
    'Watchlist',
    'ContinueWatching',
    'PasswordHistory',
    'ResetToken',
    'MovieDownload',
    'OAuth'
]