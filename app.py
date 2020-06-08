import json
import re
from datetime import datetime, timedelta
from secrets import token_hex
from flask import Flask, request
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from objects import Retour

## FILE UPLOAD
import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/home/itha/Dev/ETNA/myFlaskAPI/public'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mkv'}

## VIDEO LENGTH
import subprocess

def get_length(filename):
    result = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                            "format=duration", "-of",
                            "default=noprint_wrappers=1:nokey=1", filename],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    return int(float(result.stdout)) + 1

## REGEX
wordRe = re.compile('[a-zA-Z0-9_-]')
emailRe = re.compile('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')

## APP
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://user@localhost:3306/mydb'
db = SQLAlchemy(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
        backref=db.backref('owner_token', lazy=True))

class Video(db.Model, JsonableModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(45), nullable=False)
    duration = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User',
        backref=db.backref('owner_videos', lazy=True))
    source = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())
    view = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if tokenObj is None:
            return { 'message': 'Token is invalid' }, 400
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def hello_world():
    return 'Hello, World!'


# TODO s'occuper du type d'auth (voir cahier des charges)
# TODO corriger les GET avec params

# TODO Hachage
@app.route('/user', methods=['POST'])
def post_user():
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


@app.route('/user/<id>', methods=['DELETE', 'PUT', 'GET'])
@login_required
def update_user(id):
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

    if request.method == 'GET':
        user = User.query.filter_by(id=id).first()
        if user is not None:
            return { 'message': 'OK', 'data': user.as_dict() }, 200
        else:
            return Retour.create_error('Bad Request', 400, ['resource does not exist']), 400


@app.route('/users', methods=['GET'])
def list_users():
    if request.method == 'GET':
        pseudo = request.args.get('pseudo')
        page = int(request.args.get('page'))
        page = 1 if page is None else page
        perPage = int(request.args['perPage'])
        perPage = 5 if perPage is None else perPage

        if (pseudo is not None):
            users = User.query.filter_by(pseudo=pseudo).order_by(text('id desc')).all()
            length = len(users)
            total = int(len(users) / perPage)
            total = total + 1 if len(users) % perPage != 0 else total
            startIndex = perPage * (page - 1)
            endIndex = perPage * page
            printableUsers = []
            for user in users:
                printableUsers.append(user.as_dict())
            return { 'message': 'OK', 'data': printableUsers[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
        else:
            return Retour.create_error('Bad Request', 400, ['Bad Params']), 400
    return Retour.create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405

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

@app.route('/user/<id>/video', methods=['POST'])
# @login_required
def upload_video(id):
    if request.method == 'POST':
        if 'file' not in request.files:
            return Retour.create_error('Bad Request', 400, ['no file sent']), 400
        file = request.files['file']
        if file.filename == '':
            return Retour.create_error('Bad Request', 400, ['no file sent']), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            i = 0
            while (os.path.isfile(filepath)):
                i += 1
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(i) + '_' + filename)
            file.save(filepath)
            newVideo = Video(name=filename,
                            duration=get_length(filepath),
                            user_id=id,
                            source=str(i) + '_' + filename,
                            view=0,
                            enabled=1)
            db.session.add(newVideo)
            db.session.commit()
            return { 'message': 'OK', 'data': newVideo.as_dict() }
    return Retour.create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405

#TODO gerer user string or int
@app.route('/videos', methods=['GET'])
def list_videos():
    if request.method == 'GET':
        name = request.json.get('name')
        user_id = request.json.get('user')
        duration = request.json.get('duration')
        page = request.json.get('page')
        page = 1 if page is None else page
        perPage = request.json.get('perPage')
        perPage = 5 if perPage is None else perPage

        if name is not None:
            videos = Video.query.filter_by(name=name).order_by(text('id desc')).all()
        elif user_id is not None:
            videos = Video.query.filter_by(user_id=user_id).order_by(text('id desc')).all()
        elif duration is not None:
            videos = Video.query.filter_by(duration=duration).order_by(text('id desc')).all()
        else:
            return Retour.create_error('Bad Request', 400, ['Bad Params']), 400
        length = len(videos)
        total = int(len(videos) / perPage)
        total = total + 1 if len(videos) % perPage != 0 else total
        startIndex = perPage * (page - 1)
        endIndex = perPage * page
        printableVideos = []
        for video in videos:
            printableVideos.append(video.as_dict())
        return { 'message': 'OK', 'data': printableVideos[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
    return Retour.create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405