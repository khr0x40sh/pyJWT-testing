import logging
import flask
from flask import Flask, request, jsonify, make_response, render_template
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from functools import wraps

## remember export FLASK_APP=server2
## export FLASK_ENV=development
app = Flask(__name__)

### EDIT BELOW TO FALSE in PROD environments
app.config["debug"] = "True"

# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'your secret key'

# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)

# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated

# User Database Route
# this route sends back list of users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})

# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify <a href="./">Back to Login </a>',200)

    user = User.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify <a href="./">Back to Login </a>',200)

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        #return make_response(jsonify({'token': token.decode('UTF-8')}), 201) # Bug 1
        response = flask.Response()
        response.set_cookie(key='x-access-token', value=token)
        response.data = "<script>window.location.replace('./')</script>"
        return response
    return make_response(
        'Could not verify <a href="./">Back to Login </a>', 200)

@app.route('/debug', methods=['GET'])
def debug():
    if app.config["debug"] == "True":
        return make_response(jsonify({'message':'DEBUG MODE ENABLED'}), 200)
    else:
        return make_response('Page Not found', 404)

def create_table():
    db.create_all()

def create_debugging_admin():
    user = User.query.filter_by(email="admin@khr0x40sh.net").first()

    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            name = "debugAdmin",
            email = "admin@khr0x40sh.net",
            password = generate_password_hash("khr0x40shadmin123")
        )
        #insert
        db.session.add(user)
        db.session.commit()

        return True
    else:
        return False

#validation for home page
def token_validated():
    token = None
    # jwt is passed in the request header
    if 'x-access-token' in request.cookies:
        token = request.cookies['x-access-token']
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            current_user = User.query \
            .filter_by(public_id=data['public_id']) \
            .first()
        except Exception as e:
            return False
        if current_user is not None:
            return True
        else:
            return False #maybe unnecessary, but left in for debugging
    else:
        return False

""" Place your wrapper/template here"""
@app.route('/', methods=['GET'])
def home():
    if token_validated():
        message = f"Placeholder"
        return render_template('placeholder_authenticated.html', message=message)
    else:
        #show login banner
        return render_template('placeholder_login.html')
"""END"""

if __name__ == '__main__':
    ##Warning!!! Do not use app on debug mode in production environments!!!
    if app.config["debug"] == "True":
        logging.basicConfig(filename="app.log", level=logging.DEBUG,
                            format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
        try:
            try:
                create_table()
            except Exception as ex:
                logging.warning("Table could not be generated. Either it exists, or there is an error")
            create_debugging_admin()
        except Exception as ex:
            logging.warning("Default debugging admin could not be added")
        app.run(debug=True)
    else:
        logging.basicConfig(filename="app.log", level=logging.WARNING,
                            format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
        app.run()
