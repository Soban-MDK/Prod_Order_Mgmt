from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField, FileField, SelectField, MultipleFileField
from wtforms.validators import DataRequired, Length, Email, ValidationError, NumberRange, Regexp
from .models import User, Product
from werkzeug.utils import secure_filename
import os


class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=7, max=15)])
    submit = SubmitField('Sign Up')

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email already registered.')

class SigninForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=7, max=15)])
    submit = SubmitField('Sign In')

class AdminSigninForm(FlaskForm):
    admin_email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=7, max=15)])
    submit = SubmitField('Sign In')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[
        DataRequired(),
        Length(max=100),
        Regexp(r'^[a-zA-Z\s]+$', message="Product name must contain only letters and spaces")
    ])
    ws_code = StringField('WS Code', validators=[
        DataRequired(),
        Regexp(r'^\d+$', message="WS Code must contain only numbers"),
        Length(min=1, max=20)
    ])
    price = FloatField('Price', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="Price must be greater than 0")
    ])
    mrp = FloatField('MRP', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="MRP must be greater than 0")
    ])
    package_size = IntegerField('Package Size', validators=[
        DataRequired(),
        NumberRange(min=1, message="Package size must be greater than 0")
    ])
    tags = StringField('Tags (comma separated)', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z\s,]+$', message="Tags must contain only letters, spaces, and commas")
    ])
    category = SelectField('Category', 
        choices=[('Medicines', 'Medicines'), ('Devices', 'Devices')],
        validators=[DataRequired()]
    )
    images = MultipleFileField('Product Images')

    def __init__(self, original_ws_code=None, *args, **kwargs):
        super(ProductForm, self).__init__(*args, **kwargs)
        self.original_ws_code = original_ws_code

    def validate_price(self, field):
        if field.data > self.mrp.data:
            raise ValidationError('Sales price cannot exceed the MRP.')

    def validate_ws_code(self, field):
        if self.original_ws_code != field.data:
            product = Product.query.filter_by(ws_code=field.data).first()
            if product:
                raise ValidationError('This WS code already exists. Please use a unique code.')

    def validate_images(self, field):
        if field.data:
            files = field.data
            if len(files) > 4:
                raise ValidationError('Maximum 4 images are allowed')
            
            for file in files:
                if file.filename != '':
                    ext = os.path.splitext(file.filename)[1][1:].lower()
                    if ext not in {'png', 'jpeg', 'jpg', 'webp'}:
                        raise ValidationError('Only .png, .jpeg, .jpg, and .webp files are allowed')
