from flask import Flask
from flask_login import LoginManager
from .models import db, User
from flask_wtf.csrf import CSRFProtect
import os
import json

def from_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return []
    return value


def create_app():
    app = Flask(__name__)

    # Configure the app
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Soban_MKT')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5432/Medkart_Data'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF globally
    app.jinja_env.filters['from_json'] = from_json

    # Initialize extensions
    csrf = CSRFProtect(app)
    csrf.init_app(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Initialize login manager
    login_manager = LoginManager()
    login_manager.login_view = 'main.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from .routes import main
    app.register_blueprint(main)

    return app
