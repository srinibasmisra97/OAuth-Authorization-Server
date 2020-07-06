from urllib.parse import unquote
from flask import request, jsonify, Response
from flask.blueprints import Blueprint

from Utils.Security import b64decode, generate_jwt, validate_password

from Entities.Clients import Clients
from Entities.Applications import Application

app_Applications = Blueprint('Applications', __name__)


@app_Applications.before_request
def before_request():
    if request.path != "/token":
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


@app_Applications.route('/register', methods=['POST'])
def register():
    """
    This api is used to register an app for the client.
    :return: 200 OK, 400 Bad Request with Key and secret in authorization header.
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

    app_name = request.form.get("name")
    api_id = request.form.get("api")
    expiry = request.form.get("exp")

    if app_name is None:
        return jsonify({
            'success': False,
            'msg': 'no app name provided'
        }), 400
    elif api_id is None:
        return jsonify({
            'success': False,
            'msg': 'no api id provided'
        }), 400
    elif expiry is None:
        expiry = 15

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    decoded = b64decode(authorization.split(" ")[1])
    email = decoded.split(":")[0]

    client = Clients(email=email)
    client.get_by_email(email=email)

    app = Application(name=app_name, api=api_id, exp=expiry)
    result, msg = app.register(client=client)

    if result is None:
        return jsonify({
            'success': False,
            'msg': msg
        })

    response = Response('', headers={
        'Authorization': "Basic " + msg
    })

    return response


@app_Applications.route('/key', methods=['PUT', 'DELETE'])
def add_api_key():
    """
    This api is used to add a pair of new api keys for an app.
    :return: 200 OK, 400 Bad Request with Key and Secret in Authorization header.
    """
    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    decoded = b64decode(authorization.split(" ")[1])
    email = decoded.split(":")[0]

    client = Clients(email=email)
    client.get_by_email(email=email)

    api_id = request.form.get("api")

    if api_id is None:
        return jsonify({
            'success': False,
            'msg': 'no api id provided'
        }), 400

    if request.method == 'PUT':
        if len(request.form) > 1:
            return jsonify({
                'success': False,
                'msg': 'too many parameters'
            }), 400

        app = Application(api=api_id)

        result, msg = app.add_key_secret(api_id=api_id)

        if result is None:
            return jsonify({
                'success': False,
                'msg': msg
            })

        response = Response('', headers={
            'Authorization': 'Basic ' + msg
        })

        return response
    elif request.method == 'DELETE':
        if len(request.form) > 2:
            return jsonify({
                'success': False,
                'msg': 'too many parameters'
            }), 400

        key = request.form.get("key")
        if key is None:
            return jsonify({
                'success': False,
                'msg': 'no api key provided'
            }), 400

        app = Application(api=api_id)
        result, msg = app.revoke_key_secret(api_id=api_id, key=key)

        if result is None:
            return jsonify({
                'success': False,
                'msg': msg
            })

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })


@app_Applications.route('/app', methods=['DELETE'])
def delete_app():
    """
    This api deletes an app for a client.
    :return: 200 OK, 400 Bad Request.
    """
    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    decoded = b64decode(authorization.split(" ")[1])
    email = decoded.split(":")[0]

    client = Clients(email=email)
    client.get_by_email(email=email)

    api_id = request.form.get("api")

    if api_id is None:
        return jsonify({
            'success': False,
            'msg': 'no api id provided'
        }), 400

    app = Application(api=api_id)
    result, msg = app.delete(api_id=api_id)
    if result is None:
        return jsonify({
            'success': False,
            'msg': msg
        })

    return jsonify({
        'success': True if result else False,
        'msg': msg
    })


@app_Applications.route('/token', methods=['POST'])
def token():
    """
    This api would return a JWT token which can be used by the client to access the database.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized.
    """
    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    client = Clients()

    api_id = request.form.get("api")
    scopes = request.form.get("scopes")
    response_type = request.form.get("response_type")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if api_id is None:
        return jsonify({
            'success': False,
            'msg': 'api is not provided'
        }), 400
    elif scopes is None:
        scopes = ""
    elif response_type is None:
        return jsonify({
            'success': False,
            'msg': 'no response type provided'
        }), 400
    elif client_id is None:
        return jsonify({
            'success': False,
            'msg': 'client id missing'
        }), 400
    elif client_secret is None:
        return jsonify({
            'success': False,
            'msg': 'client secret missing'
        }), 400

    if response_type != "token":
        return jsonify({
            'success': False,
            'msg': 'response type not allowed'
        }), 400

    scopes = unquote(scopes)

    app = Application(api=api_id)
    result = app.get_by_key_secret(api_id=api_id, key=client_id, secret=client_secret)

    client = Clients()
    client.get_by_id(oid=app.owner)

    if not result:
        return jsonify({
            'success': False,
            'msg': 'unauthorized'
        }), 401

    payload = {
        'iss': 'app:insurance:auth',
        'aud': "",
        'sub': "",
        'scopes': scopes
    }

    found = False
    exp = 15
    for app in result:
        if api_id == app['api']:
            for cred in app['creds']:
                if client_id == cred['key'] and client_secret == cred['secret']:
                    found = True
                    payload['aud'] = api_id
                    payload['sub'] = client_id
                    exp = float(app['exp'])

                    if "appid" in scopes:
                        payload['app_name'] = app['name']

                    break

    if not found:
        return jsonify({
            'success': False,
            'msg': 'unauthorized'
        }), 401

    if "openid" in scopes:
        payload['first_name'] = client.first_name
        payload['last_name'] = client.last_name
        payload['email'] = client.email

    return jsonify({
        'success': True,
        'token': generate_jwt(payload=payload, expiry=exp),
        'type': 'BearerToken',
        'scopes': scopes
    })
