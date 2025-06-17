from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from datetime import datetime

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.Column(db.String(64), nullable=True)  # Username or 'System'
    action = db.Column(db.String(128), nullable=False)  # e.g., 'login', 'password_reset', 'user_create'
    details = db.Column(db.Text, nullable=True)  # Additional details in JSON format
    result = db.Column(db.String(32), nullable=False)  # 'success', 'failure', 'error'
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    session_id = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f'<AuditLog {self.timestamp}: {self.user} - {self.action} - {self.result}>' 