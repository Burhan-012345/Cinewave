from models import db
from sqlalchemy.dialects.postgresql import JSON
from datetime import datetime

class OAuth(db.Model):
    __tablename__ = "oauth"

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(255), nullable=False)
    token = db.Column(JSON, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="oauth_accounts")

    def __repr__(self):
        return f"<OAuth {self.provider}:{self.provider_user_id}>"