from . import db
from datetime import datetime

class MovieDownload(db.Model):
    __tablename__ = 'movie_downloads'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    movie_id = db.Column(db.Integer, db.ForeignKey('movies.id'), nullable=False)
    download_token = db.Column(db.String(500), nullable=False, unique=True, index=True)
    status = db.Column(db.String(20), default='pending')  # pending, downloading, completed, failed
    file_path = db.Column(db.String(500))  # Path to the actual file
    file_size = db.Column(db.Integer)  # Size in bytes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    failed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('downloads', lazy=True))
    movie = db.relationship('Movie', backref=db.backref('downloads', lazy=True))
    
    def __repr__(self):
        return f'<MovieDownload {self.id} (User {self.user_id}, Movie {self.movie_id})>'
    
    @property
    def download_speed(self):
        """Calculate average download speed in MB/s"""
        if not self.started_at or not self.completed_at or not self.file_size:
            return 0
        
        duration = (self.completed_at - self.started_at).total_seconds()
        if duration == 0:
            return 0
        
        speed_mbps = (self.file_size / (1024 * 1024)) / duration
        return round(speed_mbps, 2)