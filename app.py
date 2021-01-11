from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'library.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'library.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    userEmail = db.Column(db.String(50))
    avatarName = db.Column(db.String(50))
    avatarColor = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Authors(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    book = db.Column(db.String(20), unique=True, nullable=False)
    country = db.Column(db.String(50), nullable=False)
    book_prize = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
            #print(data)
            return f(current_user, *args, **kwargs)
        except Exception as e:
            print(str(e))
            return jsonify({'message': 'token is invalid'})



    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False, userEmail=data['userEmail'], avatarName=data['avatarName'], avatarColor=data['avatarColor'])
    db.session.add(new_user)
    db.session.commit()

    #return jsonify({'message': 'registered successfully'})
    return jsonify({'username': data['username'], 'password': hashed_password, 'userEmail': data['userEmail'], 'avatarName': data['avatarName'], 'avatarColor': data['avatarColor']})

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    #auth = request.authorization
    auth = request.json

    username = auth.get('username')
    password = auth.get('password')
    if not auth or not username or not password:
        return make_response('1could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    print("Debug: 2")
    user = Users.query.filter_by(username=auth['username']).first()
    print("user password: ",user.password, " auth password: ",auth['password'])

    #BURAYA DİKKAT USER.PASSWORD DEĞİŞTİRİLDİ
    if check_password_hash(user.password, auth['password']):
        print("true")
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('2could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

@app.route('/login/byEmail/<userEmail>',methods=['GET'])
def loginbyUsername(userEmail):
    user = Users.query.filter_by(userEmail=userEmail).first()

    if not user:
        return jsonify({'message': 'author does not exist'})
    else:
        return jsonify({'avatarColor':user.avatarColor, 'avatarName':user.avatarName, 'email':user.userEmail, 'username':user.username})

    return make_response('2could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

#>>> encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
#'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'

#>>> jwt.decode(encoded, 'secret', algorithms=['HS256'])
#{'some': 'payload'}

@app.route('/user', methods=['GET'])
def get_all_users():
    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        result.append(user_data)

    return jsonify({'users': result})


@app.route('/authors', methods=['GET'])
@token_required
def get_authors(current_user):
    authors = Authors.query.all()
    output = []
    print(current_user)
    for author in authors:
        author_data = {}
        author_data['name'] = author.name
        author_data['book'] = author.book
        author_data['country'] = author.country
        author_data['book_prize'] = author.book_prize
        output.append(author_data)

    return jsonify({'list_of_authors': output})


@app.route('/authorsPost', methods=['POST'])
@token_required
def create_author(current_user):
    data = request.get_json()
    print(current_user)
    #print("post geldi, "+data)
    new_authors = Authors(name=data['name'], country=data['country'], book=data['book'], book_prize=True)
    db.session.add(new_authors)
    db.session.commit()

    return jsonify({'message': 'new author created'})


@app.route('/authors/<name>', methods=['DELETE'])
@token_required
def delete_author(current_user, name):
    author = Authors.query.filter_by(name=name).first()
    if not author:
        return jsonify({'message': 'author does not exist'})

    db.session.delete(author)
    db.session.commit()

    return jsonify({'message': 'Author deleted'})


if __name__ == '__main__':
    app.run(debug=True)
