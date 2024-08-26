from flask import Blueprint, render_template, redirect, url_for, flash, request
from .forms import LoginForm, RegistrationForm
from .models import User
from . import db, bcrypt
from flask_login import login_user, login_required, logout_user, current_user
import pickle
import numpy as np
import pandas as pd
import sklearn
import os
from datetime import datetime
import pickle
from sklearn.preprocessing import StandardScaler
import joblib




main = Blueprint('main', __name__)

# Get the directory where this script resides
basedir = os.path.abspath(os.path.dirname(__file__))

# Load the model
model = joblib.load( os.path.join(basedir, 'random_forest_model.pkl'))
# Load the scaler
scaler = joblib.load(os.path.join(basedir, 'scaler.pkl'))
# minmaxscaler_path = os.path.join(basedir, 'minmaxscaler.pkl')

def get_greeting():
    current_time = datetime.now().time()
    if current_time < datetime.strptime('12:00:00', '%H:%M:%S').time():
        return "Good Morning"
    elif current_time < datetime.strptime('18:00:00', '%H:%M:%S').time():
        return "Good Afternoon"
    else:
        return "Good Evening"


@main.route('/')
def home():
    return render_template('home.html')
@main.route('/crop-detail')
def cropDetail():
    return render_template('crop-detail.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not bcrypt.check_password_hash(user.password_hash, form.password.data):
            error = 'Invalid credentials'
            form.username.data = ''
            form.password.data = ''
            flash('Invalid credentials','error')
        else:
            login_user(user)
            return redirect(url_for('main.dashboard'))
    return render_template('login.html', form=form, error=error)



@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    greeting = get_greeting()
    return render_template('dashboard.html', first_name=current_user.first_name, greeting=greeting)


@main.route("/predict", methods=['POST'])
def predict():
        N = request.form['Nitrogen']
        P = request.form['Phosporus']
        K = request.form['Potassium']
        temp = request.form['Temperature']
        humidity = request.form['Humidity']
        ph = request.form['Ph']
        rainfall = request.form['Rainfall']

        # Scale the input data
        input_data = scaler.transform([[N,P , K, humidity, rainfall, ph, temp]])
        prediction = model.predict(input_data)
        # single_pred = np.array(feature_list).reshape(1, -1)

        # mx_features = mx.transform(single_pred)
        # sc_mx_features = sc.transform(mx_features)
        # prediction = model.predict(sc_mx_features)

        # crop_dict = {1: "Rice", 2: "Maize", 3: "Jute", 4: "Cotton", 5: "Coconut", 6: "Papaya", 7: "Orange",
        #             8: "Apple", 9: "Muskmelon", 10: "Watermelon", 11: "Grapes", 12: "Mango", 13: "Banana",
        #             14: "Pomegranate", 15: "Lentil", 16: "Blackgram", 17: "Mungbean", 18: "Mothbeans",
        #             19: "Pigeonpeas", 20: "Kidneybeans", 21: "Chickpea", 22: "Coffee"}

        if prediction[0]:
            result = prediction[0]
        else:
            result = "Sorry, we could not determine the best crop to be cultivated with the provided data."
            
        greeting =get_greeting()    
        return render_template('dashboard.html',result = result, first_name=current_user.first_name, greeting=greeting)


@main.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if email already exists
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered. Please choose a different one or log in.', 'danger')
            return redirect(url_for('main.register'))
        
        # If email doesn't exist, proceed with registration
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        new_user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful!', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html', form=form)


@main.route('/crops', methods=['GET','POST'])
def crops():
    greeting = get_greeting()
    return render_template('crops.html', first_name=current_user.first_name, greeting=greeting)

@main.route('/about', methods=['GET','POST'])
def about():
    greeting = get_greeting()
    return render_template('about.html', first_name=current_user.first_name, greeting=greeting)