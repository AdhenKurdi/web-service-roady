import pymysql
pymysql.install_as_MySQLdb()
from datetime import datetime

from flask import Flask, render_template, current_app, make_response, request
from flask_mail import Mail, Message
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

import jwt

app = Flask(__name__,template_folder='templates')
api = Api(app)


app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:F5ggny3GprmR5R8Y1BLo@containers-us-west-115.railway.app:5441/railway"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['JWT_SECRET_KEY'] = "Rahasia"
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "vinskuy703@gmail.com"
app.config['MAIL_PASSWORD'] = "uztxdozpilfpbnog"

db = SQLAlchemy(app)

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    name = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255),unique=True,nullable=False)
    password = db.Column(db.String(255),nullable=False)
    is_verify = db.Column(db.Integer(),nullable=False)

parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('name', type=str, help='Fullname', location='json', required=True)
parser4SignUp.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignUp.add_argument('password', type=str, help='Password', location='json', required=True)
parser4SignUp.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/user/signup')
class Registration(Resource):
    @api.expect(parser4SignUp)
    def post(self):
        args = parser4SignUp.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']
        rePassword = args['re_password']

        # Check if the passwords match
        if(password != rePassword):
            return {'message' : 'Password is not match'}, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()

        # Check if the email address is already used
        if(user):
            return {'message' : 'Your email address has been used'}, 409

        try:
            # Create a new User object
            user = User(email=email, name=name, password=generate_password_hash(password), is_verify=False)

            # Add the user to the session and commit the changes to the database
            db.session.add(user)
            db.session.commit()
            
            datas = db.session.execute(db.select(User).filter_by(email=email)).first()

            user_id = datas[0].id
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
            
            url = f"https://broady-production.up.railway.app/user/verify-account/{email_token}"

            data = {
                'name': name,
                'url': url
            }

            sender = "vinskuy703@gmail.com"
            msg = Message(subject="Verify your email", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)

            mail.send(msg)
            return {
                'message' : "Success create account, check email to verify"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500

@api.route("/user/verify-account/<token>")
class VerifyAccount(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()[0]
            
            if not user:
                return {"message": "User not found"}, 404

            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Account has been verified'), 400)
                response.headers['Content-Type'] = 'text/html'

                return response

            user.is_verify = True
            db.session.commit()

            response = make_response(render_template('response.html', success=True, message='Yeay... your account has been verified!'), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500

###LOGIN###

parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/signin')
class Login(Resource):
    @api.expect(parser4SignIn)
    def post(self):
        args = parser4SignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and password" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 400

        if not user[0].is_verify :
            return { "message" : "Account not actived, check email for verify" }, 401

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }
            

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")
            print(f"INFO {jwt_secret_key}")
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
            return{ 'token' : token }, 200

        else:
            return { "message" : "Wrong password" }


###CURRENT###

@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            return {
                'status': "Success", 
                'data': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }, 200

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

###UPDATEPROFILE###

user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, help='Fullname', location='json', required=True)
user_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/update')
class UpdateUser(Resource):
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            args = user_parser.parse_args()

            user.name = args['name']
            user.email = args['email']

            db.session.commit()

            try:
                db.session.commit()
                return {'message': 'Profile updated successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

###FORGOTPASSWORD###

forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/forgot-password')
class ForgetPassword(Resource):
    def post(self):
        try:
            args = forgot_password_parser.parse_args()
            email = args['email']

            user = db.session.execute(db.select(User).filter_by(email=email)).first()

            if not user:
                return {'message': 'Email does not match any user'}, 404

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user[0].id}, jwt_secret_key, algorithm="HS256")

            url = f"https://broady-production.up.railway.app/user/reset-password/{email_token}"

            sender = "vinskuy703@gmail.com"
            msg = Message(subject="Reset your password", sender=sender, recipients=[email])
            msg.html = render_template("reset-password.html", url=url)

            mail.send(msg)
            return {'message' : "Success send request, check email to verify"}, 200

        except Exception as e:
            return {"message": f"Error {e}"}, 500



##VIEWRESETPASSWORD##

@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=user[0].id), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500


##RESETPASSWORD##

reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('id', type=int, required=True, help='User ID is required')
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')
reset_password_parser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        args = reset_password_parser.parse_args()
        password = args['password']

        user = db.session.execute(db.select(User).filter_by(id=args['id'])).first()
        if not user:
            return {'message': 'User not found'}, 404

        if password != args['confirmPassword']:
            return {'message': 'Passwords do not match'}, 400

        user[0].password = generate_password_hash(password)

        try:
            db.session.commit()
            response = make_response(render_template('response.html', success=True, message='Password has been reset successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except:
            db.session.rollback()
            response = make_response(render_template('response.html', success=False, message='Reset password failed'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response


class Jalan(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    tingkat_kerusakan = db.Column(db.String(255),nullable=False)
    lokasi = db.Column(db.String(255),nullable=False)
    img = db.Column(db.String(250), nullable=False)
    created_At = db.Column(db.DateTime, nullable=False)

    def serialize(row):
        return {
            "id" : str(row.id),
            "tingkat_kerusakan" : row.tingkat_kerusakan,
            "lokasi": row.lokasi,
            "img": row.img,
            "created_At": row.created_At
        } 

parser4ListJalan = reqparse.RequestParser()
parser4ListJalan.add_argument('kondisi', type=str, help='kondisi', location='json', required=True)
parser4ListJalan.add_argument('img', type=str, help='img', location='json', required=True)
parser4ListJalan.add_argument('lokasi', type=str, help='lokasi', location='json', required=True)

@api.route('/kondisi')
class NewJalan(Resource):
    def get(self):
        try:
            jalan = db.session.execute(db.select(Jalan)
            .order_by(Jalan.id))

            jalanX = Jalan.query.all()
            jalanY = [Jalan.serialize(x) for x in jalanX]
            
            return make_response(
                {
                    "message":"Success Get All Data",
                    "data": jalanY
                },200
            )
               
        except Exception as e:
            print(f"{e}")
            return {'message': f'Failed {e}'}, 400
        
    @api.expect(parser4ListJalan)
    def post(self):
        args = parser4ListJalan.parse_args()
        kondisi = args['kondisi']
        lokasi = args['lokasi']
        img = args['img']
        
        try:
            jalan = Jalan(tingkat_kerusakan=kondisi, lokasi=lokasi, img=img, created_At= datetime.now().date())

            db.session.add(jalan)
            db.session.commit()

            return {
                'message' : "Succes"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500

###BASIC-AUTH###

import base64
parser4BasicSignIn = reqparse.RequestParser()
parser4BasicSignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4BasicSignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/basic-signin')
class BasicLogin(Resource):
    @api.expect(parser4BasicSignIn)
    def post(self):
        args = parser4BasicSignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and password" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 400

        if not user[0].is_verify :
            return { "message" : "Account not actived, check email to verify" }, 401

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }

            payload = f"{user[0].id}:{user[0].name}:{user[0].email}"

            message_bytes = payload.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')

            return{ 'token' : base64_message }, 200
        else:
            return { "message" : "Wrong password, try again" }, 400


parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str, location='headers', required=True, help='Fill using token login')

@api.route('/user/basic-auth')
class BasicAuth(Resource):
    @api.expect(parser4Basic)
    def post(self):
        args = parser4Basic.parse_args()
        basicAuth = args['Authorization']
        base64message = basicAuth[6:]
        
        msgBytes = base64message.encode('ascii')
        base64Bytes = base64.b64decode(msgBytes)
        pair = base64Bytes.decode('ascii')
        id, name, email = pair.split(':')

        return {
            'id': id,
            'name': name,
            'email': email
        }

if __name__ == '__main__':
   app.run(debug=True, host='0.0.0.0', port=6969)
