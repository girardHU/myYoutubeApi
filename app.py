import json
import re
from datetime import datetime, timedelta
from secrets import token_hex
from flask import Flask, request
from functools import wraps
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
class JsonableModel():
    def as_dict(self):
        return { c.name: getattr(self, c.name) for c in self.__table__.columns }

class User(db.Model, JsonableModel):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), unique=True, nullable=False)
    email = db.Column(db.String(45), unique=True, nullable=False)
    pseudo = db.Column(db.String(45), nullable=True)
    password = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())

    def __repr__(self):
        return '<User %r>' % self.username

class Token(db.Model, JsonableModel):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(45), unique=True, nullable=False)
    expired_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow() + timedelta(days=1))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User',
        backref=db.backref('users', lazy=True))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if tokenObj is None:
            return { 'message': 'Token is invalid' }, 400
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def hello_world():
    return 'Hello, World!'


# TODO remove .first()

# TODO Hachage
@app.route('/user', methods=['POST'])
def user():
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
                return { 'message' : 'Ok', 'data': newUser.as_dict() }, 201
            else:
                return Retour.create_error('Bad Request', 400, ['resource already exists']), 400
        else:
            return Retour.create_error('Bad Request', 400, ['bad parameters']), 400


@app.route('/user/<id>', methods=['DELETE', 'PUT'])
@login_required
def user_delete(id):
    if request.method == 'DELETE':
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if (int(id) == tokenObj.user_id):
            userToDelete = User.query.filter_by(id=id).first()
            db.session.delete(tokenObj)
            db.session.delete(userToDelete)
            db.session.commit()
            return { 'message': 'OK', 'data': 'user deleted successfully'}, 201
        else:
            return Retour.create_error('Unauthorized', 401, ['you don\'t have access to this resource']), 401
        return Retour.create_error('Server Error', 500, ['Error while processing']), 500

    if request.method == 'PUT':
        username = request.json.get('username')
        email = request.json.get('email')
        pseudo = request.json.get('pseudo')
        password = request.json.get('password')
        if (username and email and pseudo and password is not None and
        wordRe.match(username) and emailRe.match(email)):
            userToUpdate = User.query.filter_by(username=username).first()
            if userToUpdate is not None:
                userToUpdate.email = email
                userToUpdate.pseudo = pseudo
                userToUpdate.password = password
                db.session.commit()
                return { 'message' : 'Ok', 'data': userToUpdate.as_dict() }, 201
            else:
                return Retour.create_error('Bad Request', 400, ['resource does not exist']), 400
        else:
            return Retour.create_error('Bad Request', 400, ['bad parameters']), 400


# TODO create JWT token instead of random string
@app.route('/auth', methods=['POST'])
def auth():
    if request.method == 'POST':
        login = request.json.get('login')
        password = request.json.get('password')
        if (login and password is not None and
        isinstance(login, str) and isinstance(password, str)):
            relatedUser = User.query.filter_by(username=login, password=password).first()
            if (relatedUser is not None):
                existingToken = Token.query.filter_by(user_id=relatedUser.id).first()
                if (existingToken is not None):
                    return { 'message': 'OK', 'data': existingToken.as_dict() }, 200
                else:
                    newToken = Token(code=token_hex(16), user_id=relatedUser.id)
                    db.session.add(newToken)
                    db.session.commit()
                    return { 'message': 'OK', 'data': newToken.as_dict() }, 201

            else:
                return Retour.create_error('Bad Request', 400, ['no resource found']), 400
        else:
            return Retour.create_error('Bad Request', 400, ['bad parameters']), 400
