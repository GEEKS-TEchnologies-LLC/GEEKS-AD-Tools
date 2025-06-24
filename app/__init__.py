from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import logging
import os
from flask_login import LoginManager
from logging.handlers import RotatingFileHandler
from .ad import get_ad_config, is_user_in_admin_group
from flask_migrate import Migrate

# Initialize extensions
mail = Mail()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.admin_login'

def create_app():
    app = Flask(__name__)
    
    base_dir = os.path.abspath(os.path.dirname(__file__))

    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(base_dir, 'database.db')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAIL_SERVER='localhost',
        MAIL_PORT=25,
        MAIL_USE_TLS=False,
        MAIL_USE_SSL=False,
        MAIL_DEFAULT_SENDER='noreply@example.com'
    )

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # Logging setup
    if not app.debug:
        if not os.path.exists('app/logs'):
            os.mkdir('app/logs')
        file_handler = RotatingFileHandler('app/logs/geeks_ad_plus.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('GEEKS-AD-Plus startup')

    # Register blueprints here (placeholder)
    from .views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app 

@login_manager.user_loader
def load_user(user_id):
    from .models import Admin
    return Admin.query.get(int(user_id)) 