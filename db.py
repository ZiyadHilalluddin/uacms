from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root@localhost/uacms'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)

