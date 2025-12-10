import os
from . import db
from datetime import datetime

movie_genre = db.Table('movie_genre',
    db.Column('movie_id', db.Integer, db.ForeignKey('movies.id'), primary_key=True),
    db.Column('genre_id', db.Integer, db.ForeignKey('genres.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)

class Movie(db.Model):
    __tablename__ = 'movies'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    release_year = db.Column(db.Integer)
    duration = db.Column(db.Integer)  # in minutes
    poster_url = db.Column(db.String(500))
    trailer_url = db.Column(db.String(500))
    imdb_rating = db.Column(db.Float)
    content_rating = db.Column(db.String(10))
    views_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    
    # Download related fields
    download_enabled = db.Column(db.Boolean, default=True)
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.BigInteger)  # Changed to BigInteger for large files
    file_format = db.Column(db.String(10))
    file_updated = db.Column(db.DateTime)
    download_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    reviews = db.relationship('Review', backref='movie', lazy=True, cascade='all, delete-orphan')
    watchlist_items = db.relationship('Watchlist', backref='movie', lazy=True, cascade='all, delete-orphan')
    continue_watching_items = db.relationship('ContinueWatching', backref='movie', lazy=True, cascade='all, delete-orphan')
    
    # Many-to-many with Genre
    genres = db.relationship('Genre', secondary='movie_genre', backref='movies', lazy=True)
    
    def __repr__(self):
        return f'<Movie {self.title}>'
    
    @property
    def average_rating(self):
        if not self.reviews:
            return 0
        ratings = [review.rating for review in self.reviews if review.rating is not None]
        if not ratings:
            return 0
        return sum(ratings) / len(ratings)
    
    @property
    def file_size_formatted(self):
        """Return file size in human-readable format"""
        if not self.file_size:
            return "N/A"
        
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    @property
    def download_available(self):
        """Check if download is available"""
        return self.download_enabled and self.file_path and os.path.exists(self.file_path)
    
    @property
    def actual_file_exists(self):
        """Check if the actual movie file exists on disk"""
        if not self.file_path:
            return False
        return os.path.exists(self.file_path)