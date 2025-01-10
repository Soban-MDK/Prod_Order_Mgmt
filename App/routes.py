from flask import Blueprint, render_template, request, redirect, flash, url_for
from .forms import SignupForm, SigninForm
from .models import db, User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
# bcrypt.init_app(db.app)
# 

main = Blueprint('main', __name__)

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hash the password
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('main.signin'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating account. Email may already exist.', 'danger')
    return render_template('signup.html', form=form)


@main.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SigninForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):  # Verify the password
            flash('Login successful!', 'success')
            return redirect(url_for('main.signin'))  # Redirect to a dashboard or home page
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('signin.html', form=form)
