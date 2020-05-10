from flask import Flask, render_template, redirect, session, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf.form import FlaskForm
from flask_login import login_user, logout_user, LoginManager, UserMixin, login_required, current_user, login_manager
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer 
# from flaskblog import app, db, login_manager, mail
from flask_mail import Mail, Message
import bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'key'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////Users/fdumoulin/Desktop/CLUB15/.vscode/venv/app/database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'email@gmail.com'
app.config['MAIL_PASSWORD'] = 'pass!'
mail = Mail(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(25))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')
    
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
    
@login_manager.user_loader
def loader_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=5,max=30)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=25)])

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=5,max=80)])
    username = StringField('Username', validators=[InputRequired(), Length(min=5,max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=25)])

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=5,max=80)])
    submit = SubmitField('Request Password Reset')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=25)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.password == form.password.data:
                login_user(user)
                session['logged_in'] = True
                return redirect(url_for('login'))  # change to account later
            else:
                flash('Invalid username or password.')      
    return render_template("login.html", form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data, password = form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Success! You may now login below.')
        return redirect(url_for('login'))
    return render_template("signup.html", form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = "To reset your password, click on this link:\n{}\nIf you didn't make this request ignore this email.".format(url_for('reset_token', token=token, _external=True))
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions.')
        return redirect(url_for('login'))
    return render_template("reset_password.html", title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or Experied Token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('Your password has been changed!')
        return redirect(url_for('login'))
    return render_template("reset_token.html", title='Reset Password', form=form)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session['logged_in'] = False
    return redirect(url_for('home'))

@app.route("/education")
def education():
    return render_template("education.html")

@app.route("/coding")
def coding():
    return render_template("coding.html")
    
@app.route("/jobhistory")
def jobhistory():
    return render_template("jobhistory.html")

@app.route("/tools")
def tools():
    return render_template("tools.html")

@app.route("/service")
def service():
    return render_template("service.html")


@app.route("/sports")
def sports():
    return render_template("sports.html")

@app.route("/account")
@login_required
def account():
    return render_template("account.html", name=current_user.username)


if __name__ == "__main__":
    # app.debug = True
    app.run()
