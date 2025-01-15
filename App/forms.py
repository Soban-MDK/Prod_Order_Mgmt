from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, ValidationError, NumberRange, Regexp
from .models import User, Product

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
        DataRequired(), Length(max=100)
    ])
    ws_code = StringField('WS Code', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0)])
    mrp = FloatField('MRP', validators=[DataRequired(), NumberRange(min=0)])
    package_size = IntegerField('Package Size', validators=[DataRequired()])
    tags = StringField('Tags (comma separated)', validators=[DataRequired()])
    category = SelectField('Category', choices=[('Medicines', 'Medicines'), ('Devices', 'Devices')], validators=[DataRequired()])
    images = FileField('Product Images', validators=[DataRequired()])
    submit = SubmitField('Add Product')

    def validate_sales_price(self, field):
        if self.price.data > self.mrp.data:
            raise ValidationError('Sales price cannot exceed the MRP.')

    def validate_ws_code(self, field):
        product = Product.query.filter_by(ws_code=self.ws_code.data).first()
        if product:
            raise ValidationError('WS Code must be unique. This WS code already exists.')
