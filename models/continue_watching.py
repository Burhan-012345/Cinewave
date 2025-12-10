from . import db
from datetime import datetime

class ContinueWatching(db.Model):
    __tablename__ = 'continue_watching'
    
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('profiles.id'), nullable=False)
    movie_id = db.Column(db.Integer, db.ForeignKey('movies.id'), nullable=False)
    current_time = db.Column(db.Float, default=0)  # seconds
    duration = db.Column(db.Float, default=0)  # seconds
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('profile_id', 'movie_id', name='_profile_movie_uc'),)
    
    def __repr__(self):
        return f'<ContinueWatching {self.id} (Profile {self.profile_id}, Movie {self.movie_id})>'
    
    @property
    def progress_percentage(self):
        if self.duration == 0:
            return 0
        return (self.current_time / self.duration) * 100