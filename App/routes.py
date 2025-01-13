from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for
from .forms import SigninForm, SignupForm
from .models import User, db
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token
from flask_wtf.csrf import CSRFProtect

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