from flask import Flask
from .models import db, User

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = "Soban_MKT"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5432/Medkart_Data'

    db.init_app(app)
    with app.app_context():
        db.create_all()


    from .routes import main
    app.register_blueprint(main)
    
    return app
