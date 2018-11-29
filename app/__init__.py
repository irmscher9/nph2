import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:st0ltpuffi@localhost/npDB1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = b'x1cVx#cx8akxc8#05xa7x97#afVxf2skx91x0e'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ['EMAIL_USER']
app.config['MAIL_PASSWORD'] = os.environ['EMAIL_PASSWORD']
app.config['SECURITY_PASSWORD_SALT'] = '123'

# app.config['MAIL_USERNAME'] = os.environ['EMAIL_USER']
# app.config['MAIL_USERNAME'] = 'mywebsidekicks@gmail.com'
# app.config['MAIL_PASSWORD'] = 'puff1st0lt0'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
bootstrap = Bootstrap(app)
mail = Mail(app)

from app import routes, models