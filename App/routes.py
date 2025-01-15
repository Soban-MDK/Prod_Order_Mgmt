import os
import json
import jwt
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for, current_app, flash
from .forms import SigninForm, SignupForm, AdminSigninForm, ProductForm
from functools import wraps
from .models import User, db, Admin, Product
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token
from flask_wtf.csrf import CSRFProtect
from .auth_decorators import token_required

# The Blueprint object is created with the name 'main' to represent the main routes of the application.
main = Blueprint('main', __name__) 

bcrypt = Bcrypt()
csrf = CSRFProtect()

UPLOAD_FOLDER = 'App/static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Home Route
@main.route('/')
def home():
    return render_template('base.html', title='Home')

# Signup Route
@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
            try:
                db.session.add(new_user)
                db.session.commit()
                token = generate_token(new_user.id)
                return jsonify({'status': 'success', 'message': 'Account created successfully!', 'redirect': url_for('main.home')}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'status': 'error', 'message': str(e)}), 500
        else:
            return jsonify({'status': 'error', 'errors': form.errors}), 400
    
    # Render the form on GET request
    return render_template('signup.html', form=form)


# Signin Route
@main.route('/signin', methods=['GET', 'POST'])
@csrf.exempt  # Exempt this route from CSRF protection
def signin():
    if request.method == 'POST':
        # Handle both JSON and form data
        data = request.get_json() if request.is_json else request.form
        
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email and password are required'
            }), 400

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            token = generate_token(user.id)
            response = jsonify({
                'status': 'success',
                'message': 'Login successful!',
                'token': token,
                'redirect': url_for('main.home')
            })
            response.set_cookie('access_token', token, httponly=True, max_age=7*60*60)
            return response

        return jsonify({
            'status': 'error',
            'message': 'Invalid email or password'
        }), 401

    # GET request - render the form
    form = SigninForm()
    return render_template('signin.html', form=form)


# Function to check if the admin is logged in
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return redirect(url_for('main.admin_signin'))

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            admin = Admin.query.get(data['user_id'])
            if not admin:
                return redirect(url_for('main.admin_signin'))
        except:
            return redirect(url_for('main.admin_signin'))

        return f(*args, **kwargs)
    return decorated


# Admin Signin Route
@main.route('/admin/signin', methods=['GET', 'POST'])
@csrf.exempt
def admin_signin():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        admin_email = data.get('admin_email')
        password = data.get('password')

        if not admin_email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email and password are required'
            }), 400

        admin = Admin.query.filter_by(admin_email=admin_email).first()

        if admin and bcrypt.check_password_hash(admin.password, password):
            token = generate_token(admin.admin_id)
            response = jsonify({
                'status': 'success',
                'message': 'Admin login successful!',
                'token': token,
                'redirect': url_for('main.admin_dashboard')
            })
            response.set_cookie('access_token', token, httponly=True, max_age=7*60*60)
            return response

        return jsonify({
            'status': 'error',
            'message': 'Invalid admin email or password'
        }), 401

    form = AdminSigninForm()
    return render_template('admin_signin.html', form=form)



# Admin Dashboard Route
@main.route('/admin/dashboard')
@token_required
def admin_dashboard(user_id):
    """Admin dashboard with two buttons."""
    admin = Admin.query.get(user_id)
    if not admin:
        return jsonify({'message': 'Not authorized as admin!'}), 403
    return render_template('admin_dashboard.html', admin=admin)


@main.route('/manage_products', methods=['GET'])
@token_required
def manage_products(user_id):
    """Display all products and provide options to add, edit, and delete."""
    products = Product.query.all()
    return render_template('manage_products.html', products=products)


@main.route('/add_product', methods=['GET', 'POST'])
@token_required
def add_product(user_id):
    """Add new product functionality."""
    form = ProductForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            images = []
            for file in request.files.getlist('images'):
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(UPLOAD_FOLDER, filename))
                    images.append(filename)
            
            new_product = Product(
                name=form.name.data,
                ws_code=form.ws_code.data,
                price=form.price.data,
                mrp=form.mrp.data,
                package_size=form.package_size.data,
                images=json.dumps(images),
                tags=json.dumps([tag.strip() for tag in form.tags.data.split(',')]),
                category=form.category.data
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('main.manage_products'))
        else:
            return render_template('add_product.html', form=form, errors=form.errors)
    
    return render_template('add_product.html', form=form)


@main.route('/edit_product/<int:id>', methods=['GET', 'POST'])
@token_required
def edit_product(user_id, id):
    """Edit existing product."""
    product = Product.query.get_or_404(id)
    form = ProductForm(obj=product)
    
    if request.method == 'POST' and form.validate_on_submit():
        product.name = form.name.data
        product.ws_code = form.ws_code.data
        product.price = form.price.data
        product.mrp = form.mrp.data
        product.package_size = form.package_size.data
        product.tags = json.dumps([tag.strip() for tag in form.tags.data.split(',')])
        product.category = form.category.data
        
        if form.images.data:
            images = []
            for file in request.files.getlist('images'):
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(UPLOAD_FOLDER, filename))
                    images.append(filename)
            product.images = json.dumps(images)
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('main.manage_products'))
    
    return render_template('edit_product.html', form=form, product=product)


@main.route('/delete_product/<int:id>', methods=['POST'])
@token_required

def delete_product(user_id, id):
    """Delete a product."""
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('main.manage_products'))

