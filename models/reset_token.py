# reset_token.py
from . import db
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property

class ResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(500), nullable=False, unique=True, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)  
    used_at = db.Column(db.DateTime, nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add hybrid property to provide is_used alias
    @hybrid_property
    def is_used(self):
        return self.used
    
    @is_used.setter
    def is_used(self, value):
        self.used = value
    
    def __repr__(self):
        return f'<ResetToken {self.id} (User {self.user_id})>'