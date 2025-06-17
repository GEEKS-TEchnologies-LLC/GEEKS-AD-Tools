from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import logging
import os
from flask_login import LoginManager
from .models import Admin

# Initialize extensions
mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.admin_login'

def create_app():
    app = Flask(__name__)
    
    # Basic config (to be expanded)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 25
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    # Logging setup
    if not os.path.exists('app/logs'):
        os.makedirs('app/logs')
    file_handler = logging.FileHandler('app/logs/app.log')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    file_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('App startup')

    # Register blueprints here (placeholder)
    from .views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app 

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id)) 