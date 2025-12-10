from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView
from flask_login import current_user
from flask import redirect, url_for

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class SecureAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

def setup_admin(admin_app, db):
    from models import User, Profile, Movie, Genre, Review, Watchlist, ContinueWatching, PasswordHistory, ResetToken
    from models.oauth import OAuth
    from models import MovieDownload  # Add MovieDownload import
    
    # Create custom views for each model
    class UserAdmin(SecureModelView):
        column_list = ['id', 'email', 'name', 'is_active', 'is_admin', 'created_at']
        column_searchable_list = ['email', 'name']
        column_filters = ['is_active', 'is_admin', 'created_at']
        form_columns = ['email', 'name', 'password_hash', 'is_active', 'is_admin', 'theme_preference']
        
    class ProfileAdmin(SecureModelView):
        column_list = ['id', 'name', 'user_id', 'is_default', 'is_active', 'created_at']
        column_searchable_list = ['name']
        column_filters = ['is_default', 'is_active']
        form_columns = ['name', 'user_id', 'is_default', 'is_active']
        
    class MovieAdmin(SecureModelView):
        column_list = ['id', 'title', 'release_year', 'duration', 'views_count', 'download_count', 'is_featured', 'download_enabled', 'created_at']
        column_searchable_list = ['title', 'description']
        column_filters = ['release_year', 'is_featured', 'download_enabled', 'created_at']
        form_columns = ['title', 'description', 'release_year', 'duration', 'poster_url', 
                       'trailer_url', 'imdb_rating', 'content_rating', 'views_count', 
                       'download_count', 'is_featured', 'download_enabled', 'file_path',
                       'file_size', 'file_format', 'genres']
        column_formatters = {
            'file_size': lambda v, c, m, p: f"{m.file_size_formatted}" if hasattr(m, 'file_size_formatted') else f"{m.file_size} bytes"
        }
        
    class GenreAdmin(SecureModelView):
        column_list = ['id', 'name', 'description']
        column_searchable_list = ['name']
        form_columns = ['name', 'description']
        
    class ReviewAdmin(SecureModelView):
        column_list = ['id', 'user_id', 'movie_id', 'rating', 'created_at']
        column_searchable_list = ['comment']
        column_filters = ['rating', 'created_at']
        form_columns = ['user_id', 'movie_id', 'rating', 'comment']
        
    class WatchlistAdmin(SecureModelView):
        column_list = ['id', 'user_id', 'movie_id', 'created_at']
        column_searchable_list = []
        column_filters = ['created_at']
        form_columns = ['user_id', 'movie_id']
        
    class ContinueWatchingAdmin(SecureModelView):
        column_list = ['id', 'profile_id', 'movie_id', 'current_time', 'duration', 'updated_at']
        column_searchable_list = []
        column_filters = ['updated_at']
        form_columns = ['profile_id', 'movie_id', 'current_time', 'duration']
        
    class PasswordHistoryAdmin(SecureModelView):
        column_list = ['id', 'user_id', 'created_at']
        column_searchable_list = []
        column_filters = ['created_at']
        form_columns = ['user_id', 'password_hash']
        
    class ResetTokenAdmin(SecureModelView):
        column_list = ['id', 'user_id', 'is_used', 'expires_at', 'created_at']
        column_searchable_list = ['token']
        column_filters = ['is_used', 'expires_at', 'created_at']
        form_columns = ['user_id', 'token', 'is_used', 'expires_at', 'used_at']
        
    class OAuthAdmin(SecureModelView):
    # Use class constructor to set endpoint properly
        def __init__(self, model, session, **kwargs):
        # Set endpoint before calling parent constructor
            kwargs['endpoint'] = 'admin_oauth'
            super().__init__(model, session, **kwargs)
    
        column_list = ['id', 'provider', 'provider_user_id', 'user_id', 'created_at']
        column_searchable_list = ['provider_user_id', 'provider']
        column_filters = ['provider', 'created_at']
        form_columns = ['provider', 'provider_user_id', 'token', 'user_id']
        column_formatters = {
            'token': lambda v, c, m, p: f"Token: {len(str(m.token))} chars"
        }
        
    class MovieDownloadAdmin(SecureModelView):
        column_list = ['id', 'user_id', 'movie_id', 'status', 'file_size', 'download_token', 'created_at', 'completed_at']
        column_searchable_list = ['download_token']
        column_filters = ['status', 'created_at']
        form_columns = ['user_id', 'movie_id', 'status', 'file_size', 'download_token', 'file_path', 'error_message']
        column_formatters = {
            'file_size': lambda v, c, m, p: f"{m.file_size_formatted}" if hasattr(m, 'file_size_formatted') else f"{m.file_size} bytes",
            'download_token': lambda v, c, m, p: f"{m.download_token[:15]}..." if m.download_token else None
        }
    
    # Add views with custom configurations
    admin_app.add_view(UserAdmin(User, db.session, name='Users', category='User Management'))
    admin_app.add_view(ProfileAdmin(Profile, db.session, name='Profiles', category='User Management'))
    admin_app.add_view(PasswordHistoryAdmin(PasswordHistory, db.session, name='Password History', category='Security'))
    admin_app.add_view(ResetTokenAdmin(ResetToken, db.session, name='Reset Tokens', category='Security'))
    admin_app.add_view(OAuthAdmin(OAuth, db.session, name='OAuth Connections', category='Security'))
    
    admin_app.add_view(MovieAdmin(Movie, db.session, name='Movies', category='Content'))
    admin_app.add_view(GenreAdmin(Genre, db.session, name='Genres', category='Content'))
    admin_app.add_view(ReviewAdmin(Review, db.session, name='Reviews', category='Content'))
    
    admin_app.add_view(WatchlistAdmin(Watchlist, db.session, name='Watchlist', category='User Data'))
    admin_app.add_view(ContinueWatchingAdmin(ContinueWatching, db.session, name='Continue Watching', category='User Data'))
    admin_app.add_view(MovieDownloadAdmin(MovieDownload, db.session, name='Downloads', category='User Data'))