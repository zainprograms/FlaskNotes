from flask import Blueprint, render_template, redirect, url_for, request, flash
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
        if request.method == "POST":
            email = request.form.get('email')
            password = request.form.get('password')

            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
                else:
                    flash('Incorrect password try again', category='error')
            else:
                flash(f'User dosent exists', category='error')

        return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def Sign_up():
    if request.method == "POST":
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exist', category='error')
        elif len(email) < 4:
            flash("Email must be greater then 3 Characters", category='error')
        elif len(firstName) < 3:
            flash("Firstname should at least have 2 characters", category='error')
        elif password1 != password2:
            flash("Passwords Dosent match", category='error')
        elif len(password1) < 4:
            flash("password must have greater then 3 characters", category='error')
        else:
            new_user = User(email=email, first_name=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created", category='successful')
            login_user(user, remember=True)
            return redirect(url_for('views.home'))
    return render_template("sign-up.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))