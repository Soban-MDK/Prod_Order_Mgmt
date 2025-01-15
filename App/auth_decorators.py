from flask import request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os
import uuid

from .models import Admin
from flask import redirect, url_for


SECRET_KEY = os.getenv('SECRET_KEY', 'Soban_MKT')

def generate_token(user_id, is_admin=False):
    """Generate JWT token with admin flag."""
    payload = {
        'user_id': user_id,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(hours=7),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(data['user_id'], *args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        
        if not token:
            if request.is_json:
                return jsonify({'message': 'Token is missing!'}), 401
            return redirect(url_for('main.admin_signin'))

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Check if the token has admin privileges
            if not data.get('is_admin', False):
                if request.is_json:
                    return jsonify({'message': 'Admin privileges required!'}), 403
                return redirect(url_for('main.admin_signin'))

            # Check if the admin exists in database
            admin = Admin.query.get(data['user_id'])
            if not admin:
                if request.is_json:
                    return jsonify({'message': 'Admin not found!'}), 403
                return redirect(url_for('main.admin_signin'))

        except jwt.ExpiredSignatureError:
            if request.is_json:
                return jsonify({'message': 'Token has expired!'}), 401
            return redirect(url_for('main.admin_signin'))
        except jwt.InvalidTokenError:
            if request.is_json:
                return jsonify({'message': 'Invalid token!'}), 401
            return redirect(url_for('main.admin_signin'))

        return f(data['user_id'], *args, **kwargs)
    return decorated