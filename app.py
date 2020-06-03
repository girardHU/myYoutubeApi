import json
import re
from flask import Flask
from flask import request
from flask_sqlalchemy import SQLAlchemy
from objects import Retour

## REGEX
wordRe = re.compile('[a-zA-Z0-9_-]')
emailRe = re.compile('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')

## APP
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://user@localhost:3306/mydb'
db = SQLAlchemy(app)

## MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), unique=True, nullable=False)
    email = db.Column(db.String(45), unique=True, nullable=False)
    pseudo = db.Column(db.String(45), nullable=True)
    password = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=db.func.now())

    def __repr__(self):
        return '<User %r>' % self.username

    def as_dict(self):
        return { c.name: getattr(self, c.name) for c in self.__table__.columns }


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/user', methods=['GET', 'POST'])
def user():
    # TODO Hachage
    if request.method == 'POST':
        username = request.json.get('username')
        email = request.json.get('email')
        pseudo = request.json.get('pseudo')
        password = request.json.get('password')
        if (username and email and password is not None and
        wordRe.match(username) and emailRe.match(email)):
            if (User.query.filter_by(username=username).first() is None and
            User.query.filter_by(email=email).first() is None):
                newUser = User(username=username,
                                email=email,
                                pseudo=pseudo,
                                password=password)
                db.session.add(newUser)
                db.session.commit()
                return { 'message' : 'Ok', 'data': newUser.as_dict() }
            else:
                return Retour.create_error('Bad Request', 400, ['resource already exists'])
        else:
            return Retour.create_error('Bad Request', 400, ['bad parameters'])

    elif request.method == 'GET':
        return 'GET User'

@app.route('/auth', methods=['POST'])
def auth():
    params = request.json
    if ('login' and 'password' in params and
    isInstance(params.get('username'), str) and isInstance(params.get('password'), str)):
        return 'OK'
