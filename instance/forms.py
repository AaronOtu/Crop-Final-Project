import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from .models import User
from werkzeug.security import check_password_hash

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()], render_kw={"class": "form-input"})
    last_name = StringField('Last Name', validators=[DataRequired()],render_kw={"class": "form-input"})
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"class": "form-input"})
    email = StringField('Email', validators=[DataRequired(), Email()],render_kw={"class": "form-input"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"class": "form-input"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')],render_kw={"class": "form-input"})
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username is already taken. Please choose a different one.")
        
    def validate_first_name(self, first_name):
        if re.match("^[0-9]*$", first_name.data):
            raise ValidationError('First name should not contain numbers.')

    def validate_last_name(self, last_name):
        if re.match("^[0-9]*$", last_name.data):
            raise ValidationError('Last name should not contain numbers.')

    def validate_password(self, password):
        if not re.search(r"[A-Z]", password.data):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r"[a-z]", password.data):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r"[0-9]", password.data):
            raise ValidationError('Password must contain at least one digit.')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password.data):
            raise ValidationError('Password must contain at least one special character.')     
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()],render_kw={"class": "form-input"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"class": "form-input"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
   
    
    # def validate_username(self, username):
    #     self.existing_user = User.query.filter_by(username=username.data).first()
    #     if not self.existing_user:
    #         raise ValidationError("Incorrect username") 
           
   