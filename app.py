from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/user' methods=['GET', 'POST'])
def user():
    if request.method == 'POST':
        return 'POST User'
    elif request.method == 'GET':
        return 'GET User'