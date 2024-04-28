from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authenticator import *
from db import db, User, Quiz, Option, UserQuizScore, Question

import bcrypt

#bcrypt method to hash password and check hashed password while log in
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(hashed_password,password):
    return bcrypt.checkpw(password.encode('utf-8'),hashed_password)

#initializing routes blueprint
routes = Blueprint('routes', __name__)

#Setting the homepage route to log in.
#Homepage will be set up later
@routes.route('/')
def index():
    return redirect(url_for('routes.login'))

#Register route
@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        role = request.form['role']
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        new_user = User(firstname=firstname, lastname=lastname, role=role, username=username, pswrd=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful. Please log in.")
        return redirect(url_for('routes.login'))
    return render_template('register.html', current_user=current_user)

#log in route
@routes.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.pswrd, password):
            role = user.role
            login_user(user)

            #Updating session for admin log in.
            if role == 'Admin':
                session['admin_logged_in'] = True
            
            # If not admin, setting the session for user logged in
            session['user_logged_in'] = True

            #return to dashboard if log in is successsfull
            return redirect(url_for('routes.dashboard'))
        
        else:
            #Flash message if log in is not successful.
            flash('Invalid username or password. Please try again.')
    
    #Render log in page for get requests
    return render_template('login.html', current_user=current_user)