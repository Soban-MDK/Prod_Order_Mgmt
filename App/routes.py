from flask import Blueprint, render_template

main = Blueprint('main', __name__)

@main.route('/signin')
def signin():
    return render_template('signin.html')

@main.route('/signup')
def signup():
    return render_template('signup.html')
