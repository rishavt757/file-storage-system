import os
from flaskproject import db, login_manager
from datetime import datetime
from flask_login import UserMixin
import base64
import onetimepass
import pytz

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)
    otp_secret = db.Column(db.String(16))

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    
    def get_totp_uri(self):
        return 'otpauth://totp/2FA:{0}?secret={1}&issuer=Mini-Project'.format(self.username, self.otp_secret)
    
    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


class File(db.Model):
    your_name = db.Column(db.String(30))
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    date_uploaded = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Asia/Kolkata')))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    key = db.Column(db.String(500), nullable=False)

    def __repr__(self):
        return f"File('{self.filename} - '{self.date_uploaded}')"