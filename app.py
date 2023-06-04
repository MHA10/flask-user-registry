import jwt as pyjwt

import utils
from dbms import app, db
from flask_migrate import Migrate
import datetime

from flask import make_response, request, render_template, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dbms.models import user as userModel
from flask_jwt_extended import create_access_token, \
    get_jwt_identity, jwt_required, \
    JWTManager, current_user, \
    create_refresh_token, set_access_cookies

from utils_activation.email import send_email
from utils_activation.token import generate_confirmation_token, confirm_token

migrate = Migrate(app, db)

jwt = JWTManager(app, add_context_processor=True)


def get_identity_if_logedin():
    try:
        return get_jwt_identity()
    except Exception:
        pass


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    """
    Missing auth header
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    if postman_notebook_request:
        return jsonify({'message': 'Need to Login.'}), 401


@jwt.expired_token_loader
def expired_token_callback(callback, callback2):
    ref_token = request.cookies.get('refresh_token_cookie')
    user = userModel.User.query. \
        filter_by(refresh_token=ref_token).first()
    try:
        pyjwt.decode(ref_token, app.config['SECRET_KEY'], algorithms="HS256")
    except:
        msg = "Expired Token"
        if user:
            user.refresh_token = None
            user.access_token = None
        db.session.commit()
        return jsonify({"message": msg})


@app.route('/', methods=['POST'])
@jwt_required(optional=True)
def login():
    try:
        data = request.get_json()
        if data:
            email = data.get('email')
            if not utils.check_email(email):
                return make_response(jsonify({
                    "message": "Invalid Email."
                }), 400)
            password = data.get('password')
            if not email or not password:
                return make_response(jsonify({
                    "message": "Email and Password are required."
                }), 400)
        else:
            return jsonify({
                'message': 'Login ::: Request Body Error'
            }), 400
        user = get_identity_if_logedin()
        if user:
            return jsonify({'message': 'Already logged in'})

        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if not user:
            msg = 'You are not registered'
            return jsonify({
                'message': msg
            }), 400

        if check_password_hash(user.password, password):
            # generates the JWT Token
            additional_claims = {"domain": email.split('@')[1], "is_activated": user.activated}
            access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
            refresh_token = create_refresh_token(identity=user.id)
            user.access_token = access_token
            user.refresh_token = refresh_token
            db.session.commit()
            resp = make_response(jsonify({"access_token": access_token, "refresh_token": refresh_token}))
            return resp
        else:
            msg = 'Incorrect Password!'
        return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Login Error',
            'error': f'{e}'
        }), 400


@app.route('/signup', methods=['POST'])
@jwt_required(optional=True)
def signup():
    try:
        data = request.get_json()
        if data:
            email = data.get('email')
            if not utils.check_email(email):
                return make_response(jsonify({
                    "message": "Invalid Email."
                }), 400)
            phone_num = data.get('phone_number')
            password = data.get('password')
            confirm_password = data.get('confirm_password')
            if not email or not phone_num or not password or not confirm_password:
                return make_response(jsonify({
                    "message": "Missing required field(s)."
                }), 400)
        else:
            return jsonify({
                'message': 'Login ::: Request Body Error'
            }), 400

        # checking for existing user
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if not user:
            user = userModel.User(
                phone_num=phone_num,
                email=email,
                password=generate_password_hash(password),
                activated_on=None,
            )
            # insert user
            db.session.add(user)
            db.session.commit()
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('activate_email', token=token, _external=True)
            html = render_template('activation-email.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
            msg = 'A confirmation email has been sent via email.'
            return jsonify({"message": msg})
        else:
            msg = 'A user with this email already exists'
            return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Signup Error',
            'error': f'{e}'
        }), 400


@app.route('/activate/<token>')
@jwt_required()
def activate_email(token):
    """
    Activate the user account
    """
    try:
        email = confirm_token(token)
        if email == current_user.email:
            user = userModel.User.query.filter_by(email=email).first_or_404()
            if user.activated:
                msg = 'Account already activated.'
                return jsonify({"message": msg})
            else:
                user.activated = True
                user.activated_on = datetime.datetime.now()
                db.session.add(user)
                db.session.commit()
                msg = 'You have activated your account. Thanks!'
                return jsonify({"message": msg})
        else:
            msg = "Invalid activation link!"
            return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Account Activation Error ::: The confirmation link is invalid or has expired.',
            'error': f'{e}'
        }), 400


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """
    This function is necessary since it places the logged-in user's data
    in the current_user
    Register a callback function that loads a user from your database whenever
    a protected route is accessed. This should return any python object on a
    successful lookup, or None if the lookup failed for any reason (for example
    if the user has been deleted from the database).
    """
    identity = jwt_data["sub"]
    return userModel.User.query.filter_by(id=identity).one_or_none()


@app.route("/refresh", methods=["GET"])
@jwt_required(refresh=True)
def refresh():
    """
    We are using the `refresh=True` options in jwt_required to only allow
    refresh tokens to access this route.
    """
    try:
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        resp = make_response(jsonify({"access token": access_token}))
        user = userModel.User.query.filter_by(id=current_user.id).first()
        user.access_token = access_token
        db.session.commit()
        set_access_cookies(resp, access_token)
        return resp
    except Exception as e:
        return jsonify({
            'message': 'Refresh Token Error',
            'error': f'{e}'
        }), 400


@app.route('/update', methods=['GET', 'POST'])
@jwt_required()
def update():
    try:
        data = request.get_json()
        if data:
            phone_num = data.get('phone_number')
            password = data.get('password')
        else:
            return jsonify({
                'message': 'Update User ::: Request Body Error'
            }), 400
        json_msg = ""
        user_to_update = userModel.User.query.filter_by(email=current_user.email).first()
        if password is not None and not check_password_hash(user_to_update.password, password):
            user_to_update.password = generate_password_hash(password)
            msg = "Password changed"
            json_msg = json_msg + ". " + msg
        if phone_num is not None and phone_num != current_user.phone_num:
            user_to_update.phone_num = phone_num
            msg = "Phone number updated"
            json_msg = json_msg + ". " + msg
        db.session.commit()
        if json_msg != "" and json_msg[0] == ".":
            json_msg = json_msg[2:]
            return jsonify({"message": json_msg}), 202
        return jsonify({'message': "Nothing to be updated"}), 200
    except Exception as e:
        return jsonify({
            'message': 'Update User Error',
            'error': f'{e}'
        }), 401


@app.route('/logout', methods=["GET"])
@jwt_required(refresh=True)
def logout():
    """
    Endpoint for revoking the current users access token. Saved the unique
    identifier (jti) for the JWT into our database.
    """
    try:
        user = userModel.User.query.filter_by(id=current_user.id).first()
        user.access_token = None
        user.refresh_token = None
        db.session.commit()
        resp = make_response(jsonify({"message": "Successfully logged out"}), 200)
        return resp
    except Exception as e:
        return jsonify({
            'message': 'User Registry Logout Error',
            'error': f'{e}'
        }), 400


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    """
    Callback function to check if a JWT exists in the database blocklist
    This function is necessary to check if the token supplied is logged out
    already
    """
    jti = jwt_payload["jti"]
    token = userModel.User.query \
        .filter_by(access_token=jti) \
        .one_or_none()

    return token is not None


@app.route('/resend')
@jwt_required()
def resend_confirmation():
    """
    Resend the account activation email
    """
    try:
        token = generate_confirmation_token(current_user.email)
        confirm_url = url_for('activate_email', token=token, _external=True)
        html = render_template('activation-email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(current_user.email, subject, html)
        msg = 'A new confirmation email has been sent.'
        return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Resend Confirmation Email Error',
            'error': f'{e}'
        }), 400


@app.route('/forgot-password', methods=['POST'])
@jwt_required(optional=True)
def forgot_password():
    try:
        # check if already logged in
        user = get_identity_if_logedin()
        if user:
            return jsonify({'message': 'Already logged in'})
        data = request.get_json()
        if data:
            email = data.get('email')
            if not utils.check_email(email):
                return make_response(jsonify({
                    "message": "Invalid Email."
                }), 400)
        else:
            return jsonify({
                'message': 'Forgot Password ::: Request Body Error'
            }), 400
        if not email:
            return jsonify({
                'message': 'Email is required.'
            }), 400
        # check account exists
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if user:
            # create email
            token = generate_confirmation_token(email)
            url = url_for('reset_password', token=token, _external=True)
            html = render_template('reset-email.html', reset_url=url)
            subject = 'Reset password'

            # send email
            send_email(email, subject, html)

            # response
            msg = 'A link to reset your password has been sent to your email!'
            return jsonify({"message": msg})
        else:
            # unregistered or unactivated account
            msg = 'Account does not exist!'
            return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Forgot Password Error',
            'error': f'{e}'
        }), 400


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@jwt_required(optional=True)
def reset_password(token):
    try:
        # check if already logged in
        user = get_identity_if_logedin()
        if user:
            return jsonify({'message': 'Already logged in'})

        data = request.get_json()
        if data:
            password = data.get('password')
        else:
            return jsonify({
                'message': 'Reset Password ::: Request Body Error'
            }), 400
        if not password:
            return jsonify({
                'message': 'Password is required.'
            }), 400
        try:
            # check if token is valid email
            email = confirm_token(token)

            # check if user exists
            user = userModel.User.query \
                .filter_by(email=email) \
                .first()
            if user:
                user_to_update = userModel.User.query.filter_by(email=email).first()

                # check for new and old password
                if check_password_hash(user_to_update.password, password):
                    msg = 'We\'re sorry, but the new password you entered is the same as your previous password.'
                    return jsonify({"message": msg})

                user_to_update.password = generate_password_hash(password)
                db.session.commit()

                # response
                msg = 'Password updated successfully!'
                return jsonify({"message": msg})
        except:
            msg = 'The confirmation link is invalid or has expired.'
            return jsonify({"message": msg})
    except Exception as e:
        return jsonify({
            'message': 'Reset Password Error',
            'error': f'{e}'
        }), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
