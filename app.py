import json
import re
import requests
from datetime import datetime, timedelta
import hashlib, binascii
from secrets import token_hex
from flask import Flask, request
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from elasticsearch import Elasticsearch

## FILE UPLOAD
import os
from flask import flash, redirect, url_for
from werkzeug.utils import secure_filename

## ENCODING
import cv2

UPLOAD_FOLDER = '/home/itha/Dev/myYoutubeApi/public'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mkv'}
ALLOWED_FORMATS = {1080, 720, 480, 360, 240}

## VIDEO LENGTH
import subprocess

def get_length(filename):
    result = subprocess.run(['ffprobe', '-v', 'error', '-show_entries',
                            'format=duration', '-of',
                            'default=noprint_wrappers=1:nokey=1', filename],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    return int(float(result.stdout)) + 1

## REGEX
wordRe = re.compile('[a-zA-Z0-9_-]{3,12}')
emailRe = re.compile('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')

#ElasticSearch
es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

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
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), unique=True, nullable=False)
    email = db.Column(db.String(45), unique=True, nullable=False)
    pseudo = db.Column(db.String(45), nullable=True)
    password = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())
    tokens = db.relationship('Token', cascade='all, delete-orphan')
    videos = db.relationship('Video', cascade='all, delete-orphan')
    comments = db.relationship('Comment')

    def __repr__(self):
        return '<User %r>' % self.username

class Token(db.Model, JsonableModel):
    __tablename__ = 'token'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(45), unique=True, nullable=False)
    expired_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow() + timedelta(days=1))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User',
        backref=db.backref('owner_token', lazy=True))

    def __repr__(self):
        return '<user %r\'s token>' % self.user_id

class Video(db.Model, JsonableModel):
    __tablename__ = 'video'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(45), nullable=False)
    duration = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User',
        backref=db.backref('owner_videos', lazy=True))
    comments = db.relationship('Comment', cascade='all, delete-orphan')
    source = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())
    view = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    format = db.Column(db.JSON)

    def __repr__(self):
        return '<Video %r>' % self.source

class Comment(db.Model, JsonableModel):
    __tablename__ = 'comment'
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
    created_at = db.Column(db.DateTime(), unique=False, nullable=False, default=datetime.utcnow())

    def __repr__(self):
        return '<Comment saying : %r>' % self.body

class Mail(db.Model, JsonableModel):
    __tablename__ = 'mail'
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(1600), nullable=True)
    subject = db.Column(db.String(1600), nullable=False)
    content = db.Column(db.String(1600000), nullable=False)
    type = db.Column(db.Integer(), nullable=False)

    def __repr__(self):
        return '<Mail saying : %r>' % self.body


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if tokenObj is None:
            return { 'message': 'Token is invalid' }, 401
        return f(*args, **kwargs)
    return decorated_function

def res_ownership_required(f):
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        requestToken = request.headers.get('Authorization')
        tokenObj = Token.query.filter_by(code=requestToken).first()
        if tokenObj is not None:
            if tokenObj.user_id != user_id:
                return { 'message': 'You can\'t access this resource' }, 403
        else:
            return { 'message': 'Token is invalid' }, 401
        return f(user_id, *args, **kwargs)
    return decorated_function

def ownership(request, user_id):
    requestToken = request.headers.get('Authorization')
    tokenObj = Token.query.filter_by(code=requestToken).first()
    return tokenObj.user_id == user_id

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_error(message, code, data):
    return {
        'message': message,
        'code': code,
        'data': data
    }

def generate_pager_variables(item_list, page, perPage):
    length = len(item_list)
    total = int(length / perPage)
    total = total + 1 if length % perPage != 0 else total
    page = page if page <= total else total
    startIndex = perPage * (page - 1) if perPage * (page - 1) < length else length - perPage
    startIndex = startIndex if startIndex >= 0 else 0
    endIndex = startIndex + perPage
    return page, total, startIndex, endIndex

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

import smtplib, ssl
from email.message import EmailMessage

def send_mail(type, mail_address):
    try:
        mail = Mail.query.filter_by(type=type).first()
        msg = EmailMessage()
        msg.set_content(mail.content)
        msg['Subject'] = mail.subject
        msg['From'] = mail.sender
        msg['To'] = mail_address
        context = ssl.create_default_context()
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls(context=context)
            smtp.login(msg['From'], 'HWP123456789;')
            smtp.send_message(msg)
    except Exception as e:
        return { 'error': str(e) }
    return { 'state': 'envoyé' }

@app.errorhandler(404)
def page_not_found(e):
    return create_error('Not Found', 404, ['the uri you are requesting is not referenced',
                                            'allegedly type error']), 404

@app.route('/user', methods=['POST'])
def post_user():
    if request.method == 'POST':
        if not request.json:
            return create_error('Bad Request', 400, ['no json sent']), 400
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
            print(send_mail(1, email))
            return { 'message' : 'OK', 'data': newUser.as_dict() }, 201
        return create_error('Bad Request', 400, [error]), 400

##TODO DEMANDER POUR LE 404 SUR LE TYPING DIRECTEMENT DANS L'URL

@app.route('/user/<int:user_id>', methods=['DELETE', 'PUT', 'GET'])
@auth_required
def update_user(user_id):
    if request.method == 'DELETE':
        if ownership(request, user_id):
            print(user_id)
            userToDelete = User.query.filter_by(id=user_id).first()
            print(userToDelete.as_dict())
            # requestToken = request.headers.get('Authorization')
            # tokenObj = Token.query.filter_by(code=requestToken).first()

            # db.session.delete(tokenObj)
            db.session.delete(userToDelete)
            db.session.commit()
            return { 'message' : 'OK' }, 204
        else:
            return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403

    if request.method == 'PUT':
        if ownership(request, user_id):
            if not request.json:
                return create_error('Bad Request', 400, ['no json sent']), 400
            username = request.json.get('username')
            email = request.json.get('email')
            pseudo = request.json.get('pseudo')
            password = request.json.get('password')
            if username is None or email is None or password is None:
                error = 'missing either username, email or password'
            elif not wordRe.fullmatch(username) or not emailRe.fullmatch(email):
                error = 'either invalid username (3 to 12 chars, alphanumeric, dashes and underscores), or invalid email'
            elif (User.query.filter_by(username=username).first() is not None and User.query.filter_by(username=username).first().id != user_id or
            User.query.filter_by(email=email).first() is not None and User.query.filter_by(email=email).first().id != user_id):
                error = 'username or email already in use on another account'
            else:
                userToUpdate = User.query.filter_by(id=user_id).first()
                if userToUpdate is not None:
                    userToUpdate.username = username
                    userToUpdate.email = email
                    userToUpdate.pseudo = pseudo
                    userToUpdate.password = hash_password(password)
                    db.session.commit()
                    return { 'message' : 'OK', 'data': userToUpdate.as_dict() }, 201
                else:
                    return create_error('Not Found', 404, ['resource does not exist']), 404
            return create_error('Bad Request', 400, [error]), 400
        else:
            return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403

    if request.method == 'GET':
        user = User.query.filter_by(id=user_id).first()
        if user is not None:
            return { 'message': 'OK', 'data': user.as_dict() }, 200
        else:
            return create_error('Not Found', 404, ['resource does not exist']), 404


@app.route('/users', methods=['GET'])
def list_users():
    if request.method == 'GET':
        pseudo = None
        if request.json:
            pseudo = request.json.get('pseudo')
        page = request.args.get('page')
        perPage = request.args.get('perPage')
        try:
            if page:
                page = int(request.args.get('page'))
            page = 1 if page is None else page
            if perPage:
                perPage = int(request.args.get('perPage'))
            perPage = 5 if perPage is None else perPage
        except ValueError:
            return create_error('Bad Request', 400, ['either page, perPage or both of them are not integers']), 400

        if pseudo is not None:
            users = User.query.filter_by(pseudo=pseudo).order_by(text('id desc')).all()
        else:
            users = User.query.order_by(text('id desc')).all()
        page, total, startIndex, endIndex = generate_pager_variables(users, page, perPage)
        printableUsers = []
        for user in users:
            printableUsers.append(user.as_dict())
        if printableUsers:
            return { 'message': 'OK', 'data': printableUsers[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
        else:
            return create_error('Not Found', 404, ['No user was found']), 404

@app.route('/user/<int:user_id>/videos', methods=['GET'])
def list_videos_by_user(user_id):
    if request.method == 'GET':
        page = request.args.get('page')
        perPage = request.args.get('perPage')
        try:
            if page:
                page = int(request.args.get('page'))
            page = 1 if page is None else page
            if perPage:
                perPage = int(request.args.get('perPage'))
            perPage = 5 if perPage is None else perPage
        except ValueError:
            return create_error('Bad Request', 400, ['either page, perPage or both of them are not integers']), 400

        videos = Video.query.filter_by(user_id=user_id).order_by(text('id desc')).all()
        page, total, startIndex, endIndex = generate_pager_variables(videos, page, perPage)
        printableVideos = []
        for video in videos:
            printableVideos.append(video.as_dict())
        if printableVideos:
            return { 'message': 'OK', 'data': printableVideos[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
        else:
            return create_error('Not Found', 404, ['no resource matched your request']), 404

@app.route('/auth', methods=['POST'])
def auth():
    if request.method == 'POST':
        if not request.json:
            return create_error('Bad Request', 400, ['no json sent']), 400
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

@app.route('/user/<int:user_id>/video', methods=['POST'])
@res_ownership_required
def upload_video(user_id):
    if request.method == 'POST':
        if not request.form:
            return create_error('Bad Request', 400, ['no form sent']), 400
        name = request.form.get('name')
        resolution = int(request.form.get('format'))
        if 'file' not in request.files or name is None or not isinstance(name, str):
            return create_error('Bad Request', 400, ['either no file sent, name not given or name not an instance of string']), 400
        file = request.files['file']
        if file.filename == '':
            return create_error('Bad Request', 400, ['no file sent']), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(name)
            i = 0
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(i) + '_' + filename)
            while (os.path.isfile(filepath)):
                i += 1
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(i) + '_' + filename)
            file.save(filepath)
            newVideo = Video(name=filename,
                            duration=get_length(filepath),
                            format=[resolution],
                            user_id=user_id,
                            source=str(i) + '_' + filename,
                            view=0,
                            enabled=1)
            db.session.add(newVideo)
            db.session.commit()
            return { 'message': 'OK', 'data': newVideo.as_dict() }
        else:
            return create_error('Bad Request', 400, ['your file is most likely not matching one of the following types : mp4, avi, mkv']), 400

@app.route('/videos', methods=['GET'])
def list_videos():
    if request.method == 'GET':
        name = user = duration = None
        if request.json:
            name = request.json.get('name')
            user = request.json.get('user')
            duration = request.json.get('duration')
        page = request.args.get('page')
        perPage = request.args.get('perPage')
        try:
            if page:
                page = int(request.args.get('page'))
            page = 1 if page is None else page
            if perPage:
                perPage = int(request.args.get('perPage'))
            perPage = 5 if perPage is None else perPage
        except ValueError:
            return create_error('Bad Request', 400, ['either page, perPage or both of them are not integers']), 400

        if name is not None:
            videos = Video.query.filter_by(name=name).order_by(text('id desc')).all()
        elif user is not None and isinstance(user, int):
            videos = Video.query.filter_by(user_id=user).order_by(text('id desc')).all()
        elif user is not None and isinstance(user, str):
            videos = Video.query.join(User).filter(User.username == user).all()
        elif duration is not None:
            videos = Video.query.filter_by(duration=duration).order_by(text('id desc')).all()
        else:
            videos = Video.query.order_by(text('id desc')).all()
        page, total, startIndex, endIndex = generate_pager_variables(videos, page, perPage)
        printableVideos = []
        for video in videos:
            printableVideos.append(video.as_dict())
        if printableVideos:
            return { 'message': 'OK', 'data': printableVideos[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
        else:
            return create_error('Not Found', 404, ['no resource matched your request']), 404

@app.route('/video/<int:video_id>', methods=['PATCH', 'PUT', 'DELETE'])
@auth_required
def update_video(video_id):
    if request.method == 'PATCH':
        if not request.json:
            return create_error('Bad Request', 400, ['no json sent']), 400
        resolution = request.json.get('format')
        uri = request.json.get('uri')
        if not resolution or not uri:
            error = 'missing either format, uri or both'
        elif resolution not in ALLOWED_FORMATS:
            error = 'the format is not supported'
        elif not os.path.isabs(uri):
            error = 'uri is not valid path : try absolute'
        else:
            video = Video.query.filter_by(id=video_id).first()
            temp = video.format.copy()
            temp[format] = uri
            video.format = temp
            db.session.commit()
            return { 'message' : 'OK', 'data': video.as_dict() }, 200
        return create_error('Bad Request', 400, [error]), 400
    
    if request.method == 'PUT':
        videoToUpdate = Video.query.filter_by(id=video_id).first()
        if videoToUpdate is not None:
            if ownership(request, videoToUpdate.user_id):
                if not request.json:
                    return create_error('Bad Request', 400, ['no json sent']), 400
                name = request.json.get('name')
                user_id = request.json.get('user')
                if name is not None:
                    videoToUpdate.name = name
                if user_id is not None and isinstance(user_id, int) and User.query.filter_by(id=user_id).first() is not None:
                    videoToUpdate.user_id = user_id
                elif user_id is not None and isinstance(user_id, int) and User.query.filter_by(id=user_id).first() is None:
                    return create_error('Bad Request', 400, ['no user with this id to transfer resource to']), 400
                db.session.commit()
                return { 'message' : 'OK', 'data': videoToUpdate.as_dict() }, 200
            else:
                return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403
        else:
            return create_error('Bad Request', 400, ['resource does not exist']), 400

    if request.method == 'DELETE':
        videoToDelete = Video.query.filter_by(id=video_id).first()
        if videoToDelete is not None:
            if ownership(request, videoToDelete.user_id):
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'],videoToDelete.source))
                db.session.delete(videoToDelete)
                db.session.commit()
                return 204
            else:
                return create_error('Forbidden', 403, ['you don\'t have access to this resource']), 403
        else:
            return create_error('Bad Request', 400, ['resource does not exist']), 400

@app.route('/video/<int:video_id>/comment', methods=['POST'])
@auth_required
def post_comment(video_id):
    if request.method == 'POST':
        videoObj = Video.query.filter_by(id=video_id).first()
        if ownership(request, videoObj.user_id):
            if not request.json:
                return create_error('Bad Request', 400, ['no json sent']), 400
            body = request.json.get('body')
            if body is not None:
                newComment = Comment(body=body,
                                video_id=video_id,
                                user_id=videoObj.user_id)
                db.session.add(newComment)
                db.session.commit()
                return { 'message' : 'OK', 'data': newComment.as_dict() }, 201
            else:
                return create_error('Bad Request', 400, ['missing body']), 400
        else:
            return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403

@app.route('/video/<int:video_id>/comments', methods=['GET'])
@auth_required
def list_comments(video_id):
    if request.method == 'GET':
        videoObj = Video.query.filter_by(id=video_id).first()
        if ownership(request, videoObj.user_id):
            page = request.args.get('page')
            perPage = request.args.get('perPage')
            try:
                if page:
                    page = int(request.args.get('page'))
                page = 1 if page is None else page
                if perPage:
                    perPage = int(request.args.get('perPage'))
                perPage = 5 if perPage is None else perPage
            except ValueError:
                return create_error('Bad Request', 400, ['either page, perPage or both of them are not integers']), 400

            comments = Comment.query.filter_by(video_id=video_id).order_by(text('id desc')).all()
            page, total, startIndex, endIndex = generate_pager_variables(comments, page, perPage)
            printableComments = []
            for comment in comments:
                printableComments.append(comment.as_dict())
            return { 'message': 'OK', 'data': printableComments[startIndex:endIndex], 'pager': { 'current': page, 'total': total } }
        else:
            return create_error('Forbidden', 403, ['you don\'t have access this resource']), 403

@app.route('/mail/')

@app.route('/video/<int:video_id>/encode', methods=['PATCH'])
def encode_video(video_id):
    p240 = {426, 240}
    p360 = {640, 360}
    p480 = {854, 480}
    p720 = {1280, 720}
    p1080 = {1920, 1080}
    if request.method == 'PATCH':
        video = Video.query.filter_by(id=video_id).first()
        for reso in ALLOWED_FORMATS:
            if reso < video.format[0]:
                cap = cv2.VideoCapture('/home/itha/Dev/myYoutubeApi/public/0_videohugo1')
                print(cap)

                # Define the codec and create VideoWriter object
                fourcc = cv2.VideoWriter_fourcc(*'H264')
                out = cv2.VideoWriter('videoTest1.mp4', fourcc, 20.0, (426, 240))

                # Read until video is completed
                while(cap.isOpened()):
                    # Capture frame-by-frame
                    ret, frame = cap.read()

                    if ret == True:

                        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                        cv2.imshow('frame',gray)
                        out.write(frame)
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            break

                        # cv2.imshow('frame',frame)

                    # Break the loop
                    else:
                        break

                # When everything done, release the video capture object
                cap.release()
                out.release()


                # Closes all the frames
                cv2.destroyAllWindows()
        return 'Pending'


# @app.route('/es/test', methods=['GET'])
# def test_es():
#     res = requests.get('http://localhost:9200')
#     print(res.content)
#     return { 'succeeded': True }

# @app.route('/es/populate', methods=['GET'])
# def populate_es():
#     page = 1
#     res = requests.get('http://localhost:5000/videos?page=' + str(page) + '&perPage=100').json()
#     videos = res['data']
#     while res['pager']['current'] is not res['pager']['total']:
#         page = page + 1
#         res = requests.get('http://localhost:5000/videos?page=' + str(page) + '&perPage=100').json()
#         videos.extend(res['data'])

#     i = 1
#     for video in videos:
#         es.index(index='myYoutube', doc_type='video', id=i, body=video)
#         i = i + 1

    # es.get(index='myYoutube', doc_type='video', id=3)

    # return { 'videos' : videos }