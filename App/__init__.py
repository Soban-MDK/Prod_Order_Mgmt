from flask import Flask
from .models import db
from flask_wtf.csrf import CSRFProtect
import os

def create_app():
    app = Flask(__name__)

    # Configure the app
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Soban_MKT')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5432/Medkart_Data'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = True

    # Initialize extensions
    csrf = CSRFProtect(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Register blueprints
    from .routes import main
    app.register_blueprint(main)

    return app
