import json
import re
from datetime import datetime, timedelta
import hashlib, binascii
from secrets import token_hex
from flask import Flask, request
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

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
wordRe = re.compile('[a-zA-Z0-9_-]{3,12}')
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

class Comment(db.Model, JsonableModel):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(16000000), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User',
        backref=db.backref('owner_comments', lazy=True))
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'),
        nullable=False)
    video = db.relationship('Video',
        backref=db.backref('related_videos', lazy=True))
    # created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if tokenObj is None:
            return { 'message': 'Token is invalid' }, 401
        return f(*args, **kwargs)
    return decorated_function

def ownership(request, user_id):
    requestToken = request.headers.get('Authorization')
    tokenObj = Token.query.filter_by(code=requestToken).first()
    return tokenObj.user_id == user_id

# def res_ownership_required(f):
#     @wraps(f)
#     def decorated_function(user_id, *args, **kwargs):
#         requestToken = request.headers.get('Authorization')
#         tokenObj = Token.query.filter_by(code=requestToken).first()
#         if tokenObj.user_id != user_id:
#             return { 'message': 'You can\'t access this resource' }, 403
#         return f(*args, **kwargs)
#     return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_error(message, code, data):
    return {
        'message': message,
        'code': code,
        'data': data
    }

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                provided_password.encode('utf-8'), 
                                salt.encode('ascii'), 
                                100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

# TODO s'occuper du type d'auth (voir cahier des charges)
# TODO corriger les GET avec params

@app.route('/user', methods=['POST'])
def post_user():
    if request.method == 'POST':
        username = request.json.get('username')
        email = request.json.get('email')
        pseudo = request.json.get('pseudo')
        password = request.json.get('password')
        if username is None or email is None or password is None:
            error = 'missing either username, email or password'
        elif not wordRe.fullmatch(username) or not emailRe.fullmatch(email):
            error = 'either invalid username (3 to 12 chars, alphanumeric, dashes and underscores), or invalid email'
        elif (User.query.filter_by(username=username).first() is not None or
        User.query.filter_by(email=email).first() is not None):
            error = 'username or email already in use on another account'
        else:
            newUser = User(username=username,
                            email=email,
                            pseudo=pseudo,
                            password=hash_password(password))
            db.session.add(newUser)
            db.session.commit()
            return { 'message' : 'OK', 'data': newUser.as_dict() }, 201
        return create_error('Bad Request', 400, [error]), 400


@app.route('/user/<id>', methods=['DELETE', 'PUT', 'GET'])
@auth_required
def update_user(id):
    if request.method == 'DELETE':
        try:
            if ownership(request, int(id)):
                userToDelete = User.query.filter_by(id=id).first()
                requestToken = request.headers.get('Authorization')
                tokenObj = Token.query.filter_by(code=requestToken).first()
                db.session.delete(tokenObj)
                db.session.delete(userToDelete)
                db.session.commit()
                return { 'message' : 'OK' }, 204
            else:
                return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403
        except ValueError:
            return create_error('Bad Request', 400, ['id is not an int']), 403

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
                return { 'message' : 'OK', 'data': userToUpdate.as_dict() }, 201
            else:
                return create_error('Bad Request', 400, ['resource does not exist']), 400
        else:
            return create_error('Bad Request', 400, ['bad parameters']), 400

    if request.method == 'GET':
        user = User.query.filter_by(id=id).first()
        if user is not None:
            return { 'message': 'OK', 'data': user.as_dict() }, 200
        else:
            return create_error('Bad Request', 400, ['resource does not exist']), 400


@app.route('/users', methods=['GET'])
def list_users():
    if request.method == 'GET':
        pseudo = request.args.get('pseudo')
        page = int(request.args.get('page'))
        page = 1 if page is None else page
        perPage = int(request.args.get('perPage'))
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
            return create_error('Bad Request', 400, ['Bad Params']), 400
    return create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405

# TODO create JWT token instead of random string
@app.route('/auth', methods=['POST'])
def auth():
    if request.method == 'POST':
        login = request.json.get('login')
        password = request.json.get('password')
        error = None
        if login is None or password is None:
            error = 'missing either login, password or both'
        elif not isinstance(login, str) or not isinstance(password, str):
            error = 'login or password are not string, or both'
        if error is None:
            relatedUser = User.query.filter_by(username=login).first()
            if relatedUser is not None and verify_password(relatedUser.password, password):
                existingToken = Token.query.filter_by(user_id=relatedUser.id).first()
                if existingToken is not None:
                    return { 'message': 'OK', 'data': existingToken.as_dict() }, 200
                else:
                    newToken = Token(code=token_hex(16), user_id=relatedUser.id)
                    db.session.add(newToken)
                    db.session.commit()
                    return { 'message': 'OK', 'data': newToken.as_dict() }, 201
            else:
                error = 'user referenced with this username and password does not exist'
        return create_error('Bad Request', 400, [error]), 400

@app.route('/user/<id>/video', methods=['POST'])
# @auth_required
def upload_video(id):
    if request.method == 'POST':
        if 'file' not in request.files:
            return create_error('Bad Request', 400, ['no file sent']), 400
        file = request.files['file']
        if file.filename == '':
            return create_error('Bad Request', 400, ['no file sent']), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            i = 0
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(i) + '_' + filename)
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
    return create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405

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
            return create_error('Bad Request', 400, ['Bad Params']), 400
        length = len(videos)
        total = int(len(videos) / perPage)
        total = total + 1 if len(videos) % perPage != 0 else total
        startIndex = perPage * (page - 1)
        endIndex = perPage * page
        printableVideos = []
        for video in videos:
            printableVideos.append(video.as_dict())
        return { 'message': 'OK', 'data': printableVideos[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
    return create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405

@app.route('/video/<id>', methods=['PATCH', 'PUT', 'DELETE'])
# @auth_required
def update_video(id):
    if request.method == 'PATCH':
        # TODO step 10 / encoding
        return 'PATCH'
    
    if request.method == 'PUT':
        name = request.json.get('name')
        user_id = request.json.get('user')
        if (name and user_id is not None and
        isinstance(user_id, int)):
            videoToUpdate = Video.query.filter_by(id=id).first()
            if videoToUpdate is not None:
                videoToUpdate.name = name
                videoToUpdate.user_id = user_id
                db.session.commit()
                return { 'message' : 'OK', 'data': videoToUpdate.as_dict() }, 201
            else:
                return create_error('Bad Request', 400, ['resource does not exist']), 400
        else:
            return create_error('Bad Request', 400, ['bad parameters']), 400

    if request.method == 'DELETE':
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        videoToDelete = Video.query.filter_by(id=id).first()
        if (videoToDelete.user_id == tokenObj.user_id):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'],videoToDelete.source))
            db.session.delete(videoToDelete)
            db.session.commit()
            return 204
        else:
            return create_error('Forbidden', 403, ['you don\'t have access to this resource']), 403
        return create_error('Server Error', 500, ['Error while processing']), 500

@app.route('/video/<id>/comment', methods=['POST'])
# @auth_required
def post_comment(id):
    if request.method == 'POST':
        body = request.json.get('body')
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        videoObj = Video.query.filter_by(id=int(id)).first()
        if body is not None:
            if tokenObj.user_id == videoObj.user_id:
                newComment = Comment(body=body,
                                video_id=int(id),
                                user_id=videoObj.user_id)
                db.session.add(newComment)
                db.session.commit()
                return { 'message' : 'OK', 'data': newComment.as_dict() }, 201
            else:
                return create_error('Forbidden', 403, ['you don\'t have access to this resource']), 403
        else:
            return create_error('Bad Request', 400, ['bad parameters']), 400

@app.route('/video/<id>/comments', methods=['GET'])
# @auth_required
def list_comments(id):
    if request.method == 'GET':
        page = int(request.args.get('page'))
        page = 1 if page is None else page
        perPage = int(request.args.get('perPage'))
        perPage = 5 if perPage is None else perPage

        comments = Comment.query.filter_by(video_id=int(id)).order_by(text('id desc')).all()
        length = len(comments)
        total = int(len(comments) / perPage)
        total = total + 1 if len(comments) % perPage != 0 else total
        startIndex = perPage * (page - 1)
        endIndex = perPage * page
        printableComments = []
        for user in comments:
            printableComments.append(user.as_dict())
        return { 'message': 'OK', 'data': printableComments[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }

    return create_error('Bad Method', 405, ['you shouldn\'t be able to see that']), 405