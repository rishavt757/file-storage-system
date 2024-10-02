import pyqrcode
from flaskproject import db, bcrypt
from io import BytesIO
from flask import render_template, url_for, flash, redirect, session, abort, request, Blueprint
from flaskproject.users.forms import RegistrationForm, LoginForm, UpdateAccountForm
from flaskproject.models import User, File
from flask_login import login_user, current_user, logout_user, login_required

users = Blueprint('users', __name__)

@users.route("/")
@users.route("/login/", methods=['GET', 'POST'])
def login_func():
    if current_user.is_authenticated:
        return redirect(url_for('users.account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and user.verify_totp(form.token.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('users.account'))
        else:
            flash('Login Unsuccessful. Please check email or password or otp', 'danger')
    return render_template('login.html', title='Login', form=form)

@users.route("/register", methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.about'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        session['username'] = user.username
        # flash(f'Account created for {form.username.data}! Verify yourself using a 2fa device', 'success')
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('users.two_factor_setup', user_name=form.username.data))
    return render_template('register.html', title='Register', form=form)

@users.route('/twofactor/<user_name>')
def two_factor_setup(user_name):
    flash(f'Account created for {user_name}! Verify yourself using a 2fa device', 'info')
    if 'username' not in session:
        return redirect(url_for('main.about'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('main.about'))
    # since this page contains the sensitive qrcode, make sure the browser does not cache it
    return render_template('two-factor-setup.html', title="2FA Setup"), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}
    

@users.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for any 2FA mobile app
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('users.login_func'))

@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    
    files = File.query.filter_by(owner_id=current_user.id)
    return render_template('account.html', title='Your Account', form=form, files=files)
