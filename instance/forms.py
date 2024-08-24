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
        if not re.match("^[a-zA-Z]+$", first_name.data):
            raise ValidationError("First name can only contain letters. Please choose a different one.")
        
    def validate_last_name(self, last_name):
        if not re.match("^[a-zA-Z]+$", last_name.data):
            raise ValidationError("last name can only contain letters. Please choose a different one.")        
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()],render_kw={"class": "form-input"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"class": "form-input"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
   
    
    # def validate_username(self, username):
    #     self.existing_user = User.query.filter_by(username=username.data).first()
    #     if not self.existing_user:
    #         raise ValidationError("Incorrect username") 
           
   