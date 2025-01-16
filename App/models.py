from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    @property
    def user_id(self):
        return self.id

    def __repr__(self):
        return f'<User {self.email}>'

class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100), nullable=False)
    admin_email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<Admin {self.admin_email}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ws_code = db.Column(db.String(50), nullable=False, unique=True)
    price = db.Column(db.Float, nullable=False)
    mrp = db.Column(db.Float, nullable=False)
    package_size = db.Column(db.Integer, nullable=False)
    images = db.Column(db.JSON, nullable=False)
    tags = db.Column(db.JSON, nullable=True)
    category = db.Column(db.String(50), nullable=False)
    quantity_in_stock = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self):
        return f'<Product {self.name}>'

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    type = db.Column(db.String(10), nullable=False)  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, nullable=False)


# models.py additions

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ws_code = db.Column(db.String(50), db.ForeignKey('product.ws_code'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    product = db.relationship('Product', backref='cart_items')
    user = db.relationship('User', backref='cart_items')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    total_amount = db.Column(db.Float, nullable=False)
    
    user = db.relationship('User', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    ws_code = db.Column(db.String(50), db.ForeignKey('product.ws_code'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
    product = db.relationship('Product')