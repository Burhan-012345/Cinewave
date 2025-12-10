from . import db
from datetime import datetime

class Profile(db.Model):
    __tablename__ = 'profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    name = db.Column(db.String(50), nullable=False)
    avatar = db.Column(db.String(100), default='default.png')

    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    is_child = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow
    )

    continue_watching = db.relationship(
        'ContinueWatching',
        backref='profile',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    @property
    def continue_watching_count(self):
        """Read-only property"""
        try:
            return self.continue_watching.count()
        except:
            return 0
    
    # Add a method to safely get the count for template usage
    def get_continue_watching_count(self):
        """Safe method to get continue watching count"""
        try:
            return self.continue_watching.count()
        except:
            return 0

    def __repr__(self):
        return f"<Profile {self.name} (User {self.user_id})>"
