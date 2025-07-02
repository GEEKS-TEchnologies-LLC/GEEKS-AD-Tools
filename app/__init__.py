from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import logging
import os
from flask_login import LoginManager
from logging.handlers import RotatingFileHandler
from .ad import get_ad_config, is_user_in_admin_group
from flask_migrate import Migrate
# License validation import
from .license_utils import get_license_info, validate_license, is_base_activated
import shutil

# Initialize extensions
mail = Mail()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.admin_login'

# Add a global flag for license status
LICENSE_VALID = False

def ensure_config_json():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    example_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.example.json')
    # Create config.json from example if missing
    if not os.path.exists(config_path) and os.path.exists(example_path):
        shutil.copy(example_path, config_path)
    # Ensure required license key sections exist
    import json
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        changed = False
        for key in ['base_license_key', 'plus_license_key', 'reporting_license_key']:
            if key not in config:
                config[key] = ''
                changed = True
        if changed:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not ensure config.json structure: {e}")

def create_app():
    global LICENSE_VALID
    ensure_config_json()
    # Check base product activation
    LICENSE_VALID = is_base_activated()
    # Validate license before app creation
    license_key, product_id = get_license_info()
    if not validate_license(license_key, product_id):
        print("\nWARNING: Invalid or expired license. The application will require license entry via the web UI.\n")
    # Do not exit; always allow app to start

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

    # Database initialization with error handling
    with app.app_context():
        try:
            # Create all tables if they don't exist
            db.create_all()
            app.logger.info('Database tables created successfully')
        except Exception as e:
            app.logger.warning(f'Database initialization warning: {e}')
            # Continue without database if it's read-only or other issues
            pass

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
    try:
        return Admin.query.get(int(user_id))
    except Exception as e:
        # Handle database errors gracefully
        logging.warning(f"Failed to load user {user_id}: {e}")
        return None 