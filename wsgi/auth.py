import os
from flask import Flask, url_for, redirect, render_template, request
from flask.ext.sqlalchemy import SQLAlchemy

from flask.ext import admin, login
from flask_wtf import Form
from wtforms import TextField ,PasswordField, validators
from flask.ext.admin.contrib import sqlamodel


DEBUG = True
SECRET_KEY = 'development key'

# Create Flask application
app = Flask(__name__)

app.config['PROPAGATE_EXCEPTIONS'] = True

# Create in-memory database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'+os.environ['OPENSHIFT_DATA_DIR'] + 'test.sqlite'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


# Create user model. For simplicity, it will store passwords in plain text.
# Obviously that's not right thing to do in real world application.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(64))

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username


# Define login and registration forms (for flask-login)
class LoginForm(Form):
    login = TextField("login",  [validators.Required()])
    password = PasswordField("password", [validators.Required()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise ValidationError('Invalid user')

        if user.password != self.password.data:
            raise ValidationError('Invalid password')

    def get_user(self):
        return db.session.query(User).filter_by(login=self.login.data).first()


class RegistrationForm(Form):
    login = TextField("login",  [validators.Required()])
    email = TextField()
    password = PasswordField("password", [validators.Required()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(login=self.login.data).count() > 0:
            raise ValidationError('Duplicate username')


# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.setup_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)


# Create customized model view class
class MyModelView(sqlamodel.ModelView):
    def is_accessible(self):
        return login.current_user.is_authenticated()


# Create customized index view class
class MyAdminIndexView(admin.AdminIndexView):
    def is_accessible(self):
        return login.current_user.is_authenticated()


# Flask views
@app.route('/')
def index():
    return render_template('index.html', user=login.current_user)


@app.route('/login/', methods=('GET', 'POST'))
def login_view():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = form.get_user()
        login.login_user(user)
        return redirect(url_for('index'))

    return render_template('form.html', form=form)


@app.route('/register/', methods=('GET', 'POST'))
def register_view():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        user = User()

        form.populate_obj(user)

        db.session.add(user)
        db.session.commit()

        login.login_user(user)
        return redirect(url_for('index'))

    return render_template('form.html', form=form)


@app.route('/logout/')
def logout_view():
    login.logout_user()
    return redirect(url_for('index'))

def init_app():
    init_login()
    admin = admin.Admin(app, 'Auth', index_view=MyAdminIndexView())
    admin.add_view(MyModelView(User, db.session))
    db.create_all()

if __name__ == '__main__':
    init_app()
    app.run(debug = True)
