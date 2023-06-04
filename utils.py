import re
from flask import request
import jwt
from app import app


# function for validating an Email
def check_email(email):
    """
    This function takes in an email and checks if that email is valid or not
    """
    # regex for validating an Email
    valid_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(valid_email, email):
        return True
    return False


def get_bearer_token():
    token = None
    bearer = request.headers.get('Authorization')  # Bearer JWT token here
    if bearer and len(bearer.split()) > 1:
        token = bearer.split()[1]  # JWT token
    if not token and request.cookies.get('access_token_cookie'):  # check in cookies if not in headers
        token = request.cookies.get('access_token_cookie')
    return token


def get_domain_from_jwt():
    """
    Get domain of the logged in user
    :return:
    """
    token = get_bearer_token()
    domain = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")['domain']
    return domain
