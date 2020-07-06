from flask import request, jsonify
from flask.blueprints import Blueprint

from Utils.Security import validate_email

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

    if len(request.form) > 3:
        return jsonify({
            'success': False,
            'msg': 'too many parameters'
        }), 400

    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email")

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
    elif email is None:
        return jsonify({
            'success': False,
            'msg': 'no email provided'
        }), 400

    if not validate_email(email):
        return jsonify({
            'success': False,
            'msg': 'invalid email'
        }), 400

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

    client = Clients(first_name=str(first_name), last_name=str(last_name), email=str(email))
    status, msg = client.signup()
    return jsonify({
        'success': status,
        'msg': msg
    })
