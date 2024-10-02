import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['UPLOAD_FOLDER'] = "D:\AMITY\SEM 6\Mini-Project\Flask_Project\flaskproject\static\files"
login_manager = LoginManager(app)
login_manager.login_view = 'login_func'
login_manager.login_message_category = 'info'

from flaskproject.users.routes import users
from flaskproject.files.routes import files
from flaskproject.main.routes import main
from flaskproject.errors.handlers import errors

app.register_blueprint(users)
app.register_blueprint(files)
app.register_blueprint(main)
app.register_blueprint(errors)