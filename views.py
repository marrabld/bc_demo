from flask import render_template, jsonify, redirect, url_for, request, render_template
import app
from app import db, app
from models import node

from forms import auth_form
from flask_login import login_user, login_required, logout_user, LoginManager, current_user
from werkzeug.security import generate_password_hash, \
     check_password_hash

# ==============================#
# Make sure we are logged in before hitting the endpoints
# ==============================#
login_manager = LoginManager()
login_manager.init_app(app)


# ------------------------------#
# Create a login and signup view
# ------------------------------#

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = auth_form.SignupForm()

    if request.method == 'GET':
        return render_template('signup.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            if node.User.query.filter_by(email=form.email.data).first():
                return "Email address already exists"
            else:
                app.logger.info('Adding new user')
                newuser = node.User(form.email.data, form.password.data)
                db.session.add(newuser)
                db.session.commit()

                return "User created!!!"
        else:
            return "Form didn't validate"


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = auth_form.SignupForm()

    if request.method == 'GET':
        return render_template('login.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            user = node.User.query.filter_by(email=form.email.data).first()
            if user:
                #if user.password == form.password.data:
                if user.check_password(form.password.data):
                    login_user(user)
                    app.logger.info('Redirecting to hello world')
                    return redirect(url_for('hello_world'))
                else:
                    return "Wrong password"
            else:
                return "User doesn't exist"
    else:
        return redirect(url_for('hello_world'))


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')


@login_manager.user_loader
def load_user(email):
    return node.User.query.filter_by(email=email).first()


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello_world'))


@app.route('/')
def hello_world():
    app.logger.debug('Rendering home page')
    return render_template('index.html', current_user=current_user)


