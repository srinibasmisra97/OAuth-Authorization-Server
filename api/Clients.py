from flask import request, jsonify, Response
from flask.blueprints import Blueprint

from Utils.Security import validate_email, hash_password, check_password_requirement, b64decode, validate_password, generate_jwt

from Entities.Clients import Clients

app_Clients = Blueprint('Clients', __name__)


@app_Clients.route("/signup", methods=['POST'])
def signup():
    """
    This api is used to signup clients.
    :return: 200 OK, 400 Bad Request.
    """

    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    if request.headers.get("Authorization") is None:
        return jsonify({'success': False, 'msg': 'unauthorized'}), 401

    authorization = str(request.headers.get("Authorization").encode('ascii','ignore').decode('utf-8'))
    if authorization.split(" ")[0] != 'Basic':
        return jsonify({
            'success': False,
            'msg': 'unauthorized'
        }), 401

    decoded = b64decode(authorization.split(" ")[1])
    if ":" not in decoded:
        return jsonify({
            'success': False,
            'msg': 'no username password provided'
        }), 400

    email = decoded.split(":")[0]
    password = decoded.split(":")[1]

    if len(request.form) > 2:
        return jsonify({
            'success': False,
            'msg': 'too many parameters'
        }), 400

    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")

    if first_name is None:
        return jsonify({
            'success': False,
            'msg': 'no first name provided'
        }), 400
    elif last_name is None:
        return jsonify({
            'success': False,
            'msg': 'no last name provided'
        }), 400

    if not validate_email(email):
        return jsonify({
            'success': False,
            'msg': 'invalid email'
        }), 400

    valid, msg = check_password_requirement(password=password)
    if not valid:
        return jsonify({
            'success': valid,
            'msg': msg
        })

    if not str(first_name).isalpha():
        return jsonify({
            'success': False,
            'msg': 'invalid first name'
        }), 400

    if not str(last_name).isalpha():
        return jsonify({
            'success': False,
            'msg': 'invalid last name'
        }), 400

    client = Clients(first_name=str(first_name), last_name=str(last_name), email=str(email), password=hash_password(password=password))
    status, msg = client.signup()
    return jsonify({
        'success': status,
        'msg': msg
    })


@app_Clients.route('/signin', methods=['POST'])
def signin():
    """
    This api returns an access token for admin usage.
    :return: 200 OK, 401 Unauthorized, 400 Bad Request.
    """
    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] != 'Basic':
        return jsonify({
            'success': False,
            'msg': 'unauthorized'
        }), 401

    decoded = b64decode(authorization.split(" ")[1])
    if ":" not in decoded:
        return jsonify({
            'success': False,
            'msg': 'no username password provided'
        }), 400

    email = decoded.split(":")[0]
    password = decoded.split(":")[1]

    client = Clients(email=email)
    client_doc = client.get_by_email(email=email)

    if not client_doc:
        return jsonify({
            'success': False,
            'msg': 'please sign up first'
        })

    if not validate_password(password=password, hash=client.password):
        return jsonify({
            'success': False,
            'msg': 'invalid password'
        }), 401

    response = Response('', headers={
        'Authorization': 'Bearer ' + generate_jwt({
            'iss': 'auth-server.signin.token',
            'aud': 'admin.apis',
            'sub': str(client.id_),
            'email': client.email,
            'first_name': client.first_name,
            'last_name': client.last_name
        }, expiry=30)
    })

    return response
