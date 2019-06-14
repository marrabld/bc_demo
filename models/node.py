from app import db
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """
    Users for authentication
    """
    email = db.Column(db.String(80), primary_key=True, unique=True)
    pw_hash = db.Column(db.String(80))

    def __init__(self, email, password):
        self.pw_hash = None
        self.email = email
        self.set_password(password)

    def set_password(self, password):
        self.pw_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pw_hash, password)

    def __repr__(self):
        return '<User %r>' % self.email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.email)
