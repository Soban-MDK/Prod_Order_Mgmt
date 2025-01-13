from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for
from .forms import SigninForm, SignupForm, AdminSigninForm
from .models import User, db, Admin
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token
from flask_wtf.csrf import CSRFProtect
from .auth_decorators import token_required

main = Blueprint('main', __name__)
bcrypt = Bcrypt()
csrf = CSRFProtect()

@main.route('/')
def home():
    return render_template('base.html', title='Home')

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            token = generate_token(new_user.id)
            response = make_response(redirect(url_for('main.home')))
            response.set_cookie('access_token', token, httponly=True, max_age=7*60*60)
            return response
        except Exception as e:
            db.session.rollback()
            return render_template('signup.html', form=form, error=str(e))

    return render_template('signup.html', form=form)

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

        # Can I get the link to the database and check if the admin table exists or not? The answer is yes.
        # This can be done by using the db object from the models.py file.

        admin = db.Table('admin', db.metadata, autoload=True, autoload_with=db.engine)
        print("Soban")
        print(admin)

        # Find the admin by email
        admin = Admin.query.filter_by(admin_email=admin_email).first()

        # Using bcrypt to check the hashed password
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



@main.route('/admin/dashboard')
@token_required
def admin_dashboard(user_id):
    admin = Admin.query.get(user_id)
    if not admin:
        return jsonify({'message': 'Not authorized as admin!'}), 403
    return render_template('admin_dashboard.html', admin=admin)