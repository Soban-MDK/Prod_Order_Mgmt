from flask import Blueprint, render_template
from .forms import SignupForm, SigninForm

main = Blueprint('main', __name__)

@main.route('/signin')
def signin():
    form = SigninForm()
    return render_template('signin.html', form=form)


@main.route('/signup')
def signup():
    form = SignupForm()
    return render_template('signup.html', form=form)
