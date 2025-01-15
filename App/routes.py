import os
import json
import jwt
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for, current_app, flash
from .forms import SigninForm, SignupForm, AdminSigninForm, ProductForm
from functools import wraps
from flask_wtf import FlaskForm
from .models import User, db, Admin, Product
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token
from flask_wtf.csrf import CSRFProtect
from .auth_decorators import token_required, admin_required

# The Blueprint object is created with the name 'main' to represent the main routes of the application.
main = Blueprint('main', __name__) 

bcrypt = Bcrypt()
csrf = CSRFProtect()

UPLOAD_FOLDER = 'App/static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_product_images(files, ws_code):
    """Save product images in a folder named after the WS code."""
    upload_folder = os.path.join('App', 'static', 'uploads', str(ws_code))
    os.makedirs(upload_folder, exist_ok=True)
    
    saved_images = []
    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            saved_images.append(filename)
    return saved_images


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



# Admin Signin Route - Updated with proper token generation
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
            # Generate admin token with is_admin flag
            token = generate_token(admin.admin_id, is_admin=True)
            response = jsonify({
                'status': 'success',
                'message': 'Admin login successful!',
                'token': token,
                'redirect': url_for('main.admin_dashboard')
            })
            response.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax', max_age=7*60*60)
            return response

        return jsonify({
            'status': 'error',
            'message': 'Invalid admin email or password'
        }), 401

    form = AdminSigninForm()
    return render_template('admin_signin.html', form=form)


# Admin Dashboard Route
@main.route('/admin/dashboard')
@admin_required
def admin_dashboard(user_id):
    """Admin dashboard with two buttons."""
    admin = Admin.query.get(user_id)
    if not admin:
        return jsonify({'message': 'Not authorized as admin!'}), 403
    return render_template('admin_dashboard.html', admin=admin)


@main.route('/manage_products')
@admin_required  # Make sure this decorator is applied
def manage_products(user_id):
    """Display all products with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of products per page
    
    products = Product.query\
        .order_by(Product.id.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('manage_products.html', products=products)


@main.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product(user_id):
    form = ProductForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Save images
            images = save_product_images(request.files.getlist('images'), form.ws_code.data)
            
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
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding product: {str(e)}', 'error')
    
    return render_template('add_product.html', form=form)


@main.route('/edit_product/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_product(user_id, id):
    product = Product.query.get_or_404(id)
    form = ProductForm(original_ws_code=product.ws_code, obj=product)
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Handle images
            if form.images.data and any(file.filename for file in form.images.data):
                current_images = json.loads(product.images) if product.images else []
                new_images = save_product_images(
                    request.files.getlist('images'),
                    product.ws_code
                )
                all_images = current_images + new_images
                if len(all_images) > 4:
                    flash('Maximum 4 images allowed. Some images were not saved.', 'warning')
                    all_images = all_images[:4]
                product.images = json.dumps(all_images)
            
            # Update other fields
            product.name = form.name.data
            product.price = form.price.data
            product.mrp = form.mrp.data
            product.package_size = form.package_size.data
            product.tags = json.dumps([tag.strip() for tag in form.tags.data.split(',')])
            product.category = form.category.data
            
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('main.manage_products'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating product: {str(e)}', 'error')
    
    return render_template('edit_product.html', form=form, product=product)




@main.route('/delete_product/<int:id>', methods=['POST'])
@token_required
def delete_product(user_id, id):
    """Delete a product."""
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        
        # For regular form submit, include CSRF token
        form = FlaskForm()
        if not form.validate():
            flash('CSRF validation failed', 'error')
            return redirect(url_for('main.manage_products'))
    
    product = Product.query.get_or_404(id)
    try:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product: {str(e)}', 'error')
    
    return redirect(url_for('main.manage_products'))

