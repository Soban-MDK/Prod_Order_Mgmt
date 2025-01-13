from flask import Blueprint, render_template, request, jsonify, make_response, redirect, url_for
from .forms import SigninForm, SignupForm
from .models import User, db
from flask_bcrypt import Bcrypt
from .auth_decorators import generate_token

main = Blueprint('main', __name__)
bcrypt = Bcrypt()

# Home route
@main.route('/')
def home():
    return render_template('base.html', title='Home')

# Route to render the signup page
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

# Route to render the signin page
@main.route('/signin', methods=['GET', 'POST'])
# Exempt this route from CSRF protection
@csrf.exempt
def signin():
    form = SigninForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            token = generate_token(user.id)
            response = make_response(redirect(url_for('main.home')))
            response.set_cookie('access_token', token, httponly=True, max_age=7*60*60)
            return response

        return render_template('signin.html', form=form, error='Invalid email or password')

    return render_template('signin.html', form=form)
