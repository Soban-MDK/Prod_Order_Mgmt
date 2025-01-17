import os
import json

import jwt
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for, current_app, flash, session
from .forms import SigninForm, SignupForm, AdminSigninForm, ProductForm
from functools import wraps
from flask_wtf import FlaskForm
from .models import User, db, Admin, Product, CartItem, Order, OrderItem
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token
from flask_wtf.csrf import CSRFProtect
from .auth_decorators import token_required, admin_required
from flask_login import login_user, login_required, current_user, logout_user
from datetime import datetime

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
    return render_template('home.html', title='Home')

@main.route('/contacts')
def contacts():
    return render_template('contacts.html', title='Contact Us')

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
@csrf.exempt
def signin():
    if request.method == 'POST':
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
            login_user(user)  # Add this line
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

    form = SigninForm()
    return render_template('signin.html', form=form)


@main.route('/about')
def about():
    return render_template('about.html')

# Products Page Route
@main.route('/products')
def products():
    """Display products for customers with search and pagination."""
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 8  # Show 8 products per page
    
    query = Product.query
    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                Product.ws_code.ilike(f'%{search}%')
            )
        )
    
    products = query.order_by(Product.name).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('products.html', products=products, search=search)



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
@admin_required
def manage_products(user_id):
    """Display all products with pagination and search."""
    # Get search parameter
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Query with search filter
    query = Product.query
    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                Product.ws_code.ilike(f'%{search}%')
            )
        )
    
    # Order and paginate
    products = query.order_by(Product.id.desc()).paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    return render_template(
        'manage_products.html', 
        products=products,
        search=search
    )


@main.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product(user_id):
    form = ProductForm()
    print(form.validate_on_submit())
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Save images
            # print(12)
            images = save_product_images(request.files.getlist('images'), form.ws_code.data)
            
            new_product = Product(
                name=form.name.data,
                ws_code=form.ws_code.data,
                price=form.price.data,
                mrp=form.mrp.data,
                package_size=form.package_size.data,
                images=json.dumps(images),
                tags=json.dumps([tag.strip() for tag in form.tags.data.split(',')]),
                category=form.category.data,
                quantity_in_stock = form.quantity_in_stock.data
            )
            print(new_product)
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('main.manage_products'))
            
        except Exception as e:
            print(1234)
            db.session.rollback()
            flash(f'Error adding product: {str(e)}', 'error')
    # handel the else case 
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
            product.quantity_in_stock = form.quantity_in_stock.data
            
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('main.manage_products'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating product: {str(e)}', 'error')
    
    return render_template('edit_product.html', form=form, product=product)


# Update delete_product route to handle AJAX requests
@main.route('/delete_product/<int:id>', methods=['POST'])
@admin_required
def delete_product(user_id, id):
    """Delete a product and its images."""
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        form = FlaskForm()
        if not form.validate():
            flash('CSRF validation failed', 'error')
            return redirect(url_for('main.manage_products'))
    
    product = Product.query.get_or_404(id)
    
    try:
        # Delete product images from filesystem
        if product.images:
            print(os.path.join(UPLOAD_FOLDER, str(product.ws_code)))
            image_folder = os.path.join(UPLOAD_FOLDER, str(product.ws_code))
            if os.path.exists(image_folder):
                for image in json.loads(product.images):
                    image_path = os.path.join(image_folder, image)
                    if os.path.exists(image_path):
                        os.remove(image_path)
                os.rmdir(image_folder)
        
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product: {str(e)}', 'error')
    
    return redirect(url_for('main.manage_products'))

@main.route('/manage_orders')
@admin_required
@csrf.exempt
def manage_orders(user_id):
    """Display all orders with pagination and search."""
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Initialize query
    query = Order.query
    if search:
        query = query.filter(Order.id == search)
    
    # Get status counts
    status_counts = {
        'pending': Order.query.filter_by(status='pending').count(),
        'accepted': Order.query.filter_by(status='accepted').count(),
        'rejected': Order.query.filter_by(status='rejected').count(),
        'delivered': Order.query.filter_by(status='delivered').count()
    }
    
    # Updated case statement syntax
    status_order = db.case(
        (Order.status == 'pending', 1),
        (Order.status == 'accepted', 2),
        (Order.status == 'rejected', 3),
        (Order.status == 'delivered', 4),
        else_=5
    )
    
    # Order by status and date
    query = query.order_by(
        status_order,
        Order.order_date.desc()
    )
    
    orders = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'manage_orders.html',
        orders=orders,
        search=search,
        status_counts=status_counts
    )


@main.route('/get_product_images/<ws_code>')
def get_product_images(ws_code):
    """Get product images based on WS code."""
    product = Product.query.filter_by(ws_code=ws_code).first()
    if not product:
        return jsonify({'error': 'Product not found'}), 404
        
    if product.images:
        images = json.loads(product.images)
        image_urls = [
            url_for('static', filename=f'uploads/{product.ws_code}/{image}')
            for image in images
        ]
        return jsonify({'images': image_urls})
    return jsonify({'images': []})


@main.route('/cart')
@token_required
@login_required
def view_cart(user_id):
    """View cart contents."""
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.quantity * item.product.price for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)


@main.route('/cart/count')
@token_required
@login_required
def get_cart_count(user_id):
    """Get count of items in cart."""
    count = CartItem.query.filter_by(user_id=current_user.id).with_entities(
        db.func.sum(CartItem.quantity)
    ).scalar() or 0
    return jsonify({'count': int(count)})


@main.route('/cart/update', methods=['POST'])
@csrf.exempt
@token_required
@login_required
def update_cart(user_id):
    """Update cart item quantity."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        ws_code = data.get('ws_code')
        quantity = int(data.get('quantity', 0))
        
        cart_item = CartItem.query.filter_by(
            user_id=current_user.id, 
            ws_code=ws_code
        ).first()
        
        if not cart_item:
            return jsonify({'error': 'Cart item not found'}), 404
        
        if quantity > 0:
            # Check stock availability
            product = Product.query.filter_by(ws_code=ws_code).first()
            if product.quantity_in_stock < quantity:
                return jsonify({'error': 'Not enough stock available'}), 400
            cart_item.quantity = quantity
        else:
            db.session.delete(cart_item)
        
        db.session.commit()
        return jsonify({'message': 'Cart updated successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@main.route('/order/place', methods=['POST'])
@csrf.exempt  # Add CSRF exemption
@token_required
@login_required  # Add login required
def place_order(user_id):
    try:
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        if not cart_items:
            return jsonify({'error': 'Cart is empty'}), 400
        
        total_amount = sum(item.quantity * item.product.price for item in cart_items)
        
        # Check stock availability
        for cart_item in cart_items:
            product = Product.query.filter_by(ws_code=cart_item.ws_code).first()
            if not product:
                return jsonify({'error': f'Product with WS code {cart_item.ws_code} not found'}), 404
            if product.quantity_in_stock < cart_item.quantity:
                return jsonify({
                    'error': f'Insufficient stock for {product.name}. Available: {product.quantity_in_stock}'
                }), 400

        # Create order
        order = Order(
            user_id=current_user.id,
            total_amount=total_amount,
            status='pending'
        )
        db.session.add(order)
        
        # Create order items and update stock
        for cart_item in cart_items:
            product = Product.query.filter_by(ws_code=cart_item.ws_code).first()
            order_item = OrderItem(
                order=order,
                ws_code=cart_item.ws_code,
                quantity=cart_item.quantity,
                price=product.price
            )
            product.quantity_in_stock -= cart_item.quantity
            db.session.add(order_item)
            db.session.delete(cart_item)  # Remove item from cart
        
        db.session.commit()
        return jsonify({
            'message': 'Order placed successfully',
            'order_id': order.id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



# add the add to cart route
@main.route('/cart/add', methods=['POST'])
@csrf.exempt
@login_required
@token_required
def add_to_cart(user_id):
    try:
        """Add a product to the cart."""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        ws_code = data.get('ws_code')
        quantity = data.get('quantity', 1)
        
        if not ws_code:
            return jsonify({'error': 'WS code is required'}), 400
        if not isinstance(quantity, int) or quantity < 1:
            return jsonify({'error': 'Quantity must be a positive integer'}), 400

        product = Product.query.filter_by(ws_code=ws_code).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        if product.quantity_in_stock < quantity:
            return jsonify({'error': 'Not enough stock'}), 400

        
        cart_item = CartItem.query.filter_by(
            user_id=current_user.id, ws_code=ws_code
        ).first()
        
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(user_id=current_user.id, ws_code=ws_code, quantity=quantity, created_at=datetime.utcnow())
            db.session.add(cart_item)
        
        db.session.commit()
        return jsonify({'message': 'Product added to cart'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
    
    # try:
    #     db.session.commit()
    #     return jsonify({'message': 'Product added to cart'})
    # except Exception as e:
    #     db.session.rollback()
    #     return jsonify({'error': str(e)}), 500

@main.route('/orders')
@login_required
@token_required
def orders(user_id):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    orders = Order.query.filter_by(user_id=current_user.id)\
        .order_by(Order.order_date.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('orders.html', orders=orders)


@main.route('/order/<int:order_id>/details')
@token_required
@login_required
def order_details(user_id, order_id):
    """Get order details."""
    order = Order.query.filter_by(
        id=order_id, 
        user_id=current_user.id
    ).first()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    items = []
    for item in order.items:
        product = Product.query.filter_by(ws_code=item.ws_code).first()
        items.append({
            'product_name': product.name if product else 'Unknown Product',
            'quantity': item.quantity,
            'price': item.price,
            'ws_code': item.ws_code
        })
    
    return jsonify({
        'order': {
            'id': order.id,
            'order_date': order.order_date,
            'status': order.status,
            'total_amount': order.total_amount
        },
        'items': items
    })

@main.route('/admin/order/<int:order_id>/details')
@admin_required
def admin_order_details(user_id, order_id):
    """Get detailed order information."""
    order = Order.query.get_or_404(order_id)
    
    items = []
    for item in order.items:
        product = Product.query.filter_by(ws_code=item.ws_code).first()
        items.append({
            'product_name': product.name if product else 'Unknown Product',
            'ws_code': item.ws_code,
            'quantity': item.quantity,
            'price': item.price
        })
    
    return jsonify({
        'order': {
            'id': order.id,
            'order_date': order.order_date,
            'status': order.status,
            'total_amount': order.total_amount
        },
        'customer_name': order.user.name,
        'items': items
    })

@main.route('/admin/order/<int:order_id>/update_status', methods=['POST'])
@admin_required
@csrf.exempt
def update_order_status(user_id, order_id):
    """Update order status."""
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Status is required'}), 400

        order = Order.query.get_or_404(order_id)
        order.status = data['status']
        db.session.commit()
        
        return jsonify({'message': 'Order status updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
    
@main.route('/logout')
@login_required
def logout():
    logout_user()
    response = make_response(redirect(url_for('main.home')))
    response.delete_cookie('access_token')
    return response

@main.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout(user_id):
    logout_user()
    session.clear()
    response = make_response(redirect(url_for('main.admin_signin')))
    response.delete_cookie('access_token', domain=None, path='/')
    response.delete_cookie('session', domain=None, path='/')
    return response