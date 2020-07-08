from flask import request, jsonify, Response
from flask.blueprints import Blueprint
from bson.objectid import ObjectId

from Utils.Security import b64decode, validate_password, verify_jwt

from Entities.Clients import Clients
from Entities.Applications import Application

app_Applications = Blueprint('Applications', __name__)


@app_Applications.before_request
def before_request():
    """
        Before request email and password validation.
    """
    if request.headers.get("Authorization") is None:
        return jsonify({'success': False, 'msg': 'unauthorized'}), 401
    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] == 'Basic':
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
    elif authorization.split(" ")[0] == 'Bearer':
        token = authorization.split(" ")[1]
        headers, claims, msg = verify_jwt(token=token)
        if headers is None:
            return jsonify({
                'success': False,
                'msg': msg
            }), 401
        id = ObjectId(claims['sub'])
        email = claims['email']

        client = Clients(id_=id)
        if not client.get_by_id(oid=id):
            return jsonify({
                'success': False,
                'msg': 'user not fount'
            }), 401

        if client.email != email:
            return jsonify({
                'sucess': False,
                'msg': 'invalid email'
            }), 401
    else:
        return jsonify({'success': False, 'msg': 'invalid authorization'}), 400


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

    if len(request.form) > 5:
        return jsonify({
            'success': False,
            'msg': 'too many parameters'
        }), 400

    app_name = request.form.get("name")
    api_id = request.form.get("api")
    expiry = request.form.get("exp")
    grant_types = request.form.get("grant_types")
    redirect_uris = request.form.get("redirect_uris")

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

    if grant_types is None:
        grant_types = []
    else:
        grant_types = [gty.strip() for gty in grant_types.split(",")]

    if redirect_uris is None:
        redirect_uris = []
    else:
        redirect_uris = [uri.strip() for uri in redirect_uris.split(",")]

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] == 'Basic':
        decoded = b64decode(authorization.split(" ")[1])
        email = decoded.split(":")[0]
    elif authorization.split(" ")[0] == 'Bearer':
        headers, claims, msg = verify_jwt(authorization.split(" ")[1])
        if headers is None:
            return jsonify({'success': False, 'msg': msg}), 401
        email = claims['email']

    client = Clients(email=email)
    client.get_by_email(email=email)

    app = Application(name=app_name, api=api_id, exp=expiry, redirect_uris=redirect_uris, grant_types=grant_types)
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
    if authorization.split(" ")[0] == 'Basic':
        decoded = b64decode(authorization.split(" ")[1])
        email = decoded.split(":")[0]
    elif authorization.split(" ")[0] == 'Bearer':
        headers, claims, msg = verify_jwt(authorization.split(" ")[1])
        if headers is None:
            return jsonify({'success': False, 'msg': msg}), 401
        email = claims['email']

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
    if authorization.split(" ")[0] == 'Basic':
        decoded = b64decode(authorization.split(" ")[1])
        email = decoded.split(":")[0]
    elif authorization.split(" ")[0] == 'Bearer':
        headers, claims, msg = verify_jwt(authorization.split(" ")[1])
        if headers is None:
            return jsonify({'success': False, 'msg': msg}), 401
        email = claims['email']

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

    client.remove_app(application=app)

    return jsonify({
        'success': True if result else False,
        'msg': msg
    })


@app_Applications.route('/uris', methods=['PUT'])
def set_uris():
    """
    This API sets the redirect_uris of the application.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized.
    """
    if request.headers.get('Content-Type') != "application/json":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] == 'Basic':
        decoded = b64decode(authorization.split(" ")[1])
        email = decoded.split(":")[0]
    elif authorization.split(" ")[0] == 'Bearer':
        headers, claims, msg = verify_jwt(authorization.split(" ")[1])
        if headers is None:
            return jsonify({'success': False, 'msg': msg}), 401
        email = claims['email']

    client = Clients(email=email)
    client.get_by_email(email=email)

    request_data = request.get_json()

    api_id = request_data.get("api")
    if api_id is None:
        return jsonify({'success': False, 'msg': 'no api id provided'}), 400

    app = Application(api=api_id)
    result = app.get_by_api_id(api_id=api_id)

    if not result:
        return jsonify({
            'success': False,
            'msg': 'app not found'
        })

    uris = request_data.get("uris")
    if uris is None:
        return jsonify({'success': False, 'msg': 'no uris provided'}), 400

    result, msg = app.set_redirect_uris(uris=uris)

    return jsonify({
        'success': True if result else False,
        'msg': msg
    })


@app_Applications.route('/gtypes', methods=['PUT'])
def set_gtypes():
    """
    This API sets the allowed grant_types of the application.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized.
    """
    if request.headers.get('Content-Type') != "application/json":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] == 'Basic':
        decoded = b64decode(authorization.split(" ")[1])
        email = decoded.split(":")[0]
    elif authorization.split(" ")[0] == 'Bearer':
        headers, claims, msg = verify_jwt(authorization.split(" ")[1])
        if headers is None:
            return jsonify({'success': False, 'msg': msg}), 401
        email = claims['email']

    client = Clients(email=email)
    client.get_by_email(email=email)

    request_data = request.get_json()

    api_id = request_data.get("api")
    if api_id is None:
        return jsonify({'success': False, 'msg': 'no api id provided'}), 400

    app = Application(api=api_id)
    result = app.get_by_api_id(api_id=api_id)

    if not result:
        return jsonify({
            'success': False,
            'msg': 'app not found'
        })

    grant_types = request_data.get("grant_types")
    if grant_types is None:
        return jsonify({'success': False, 'msg': 'no grant_types provided'}), 400

    result, msg = app.set_grant_types(grant_types=grant_types)

    return jsonify({
        'success': True if result else False,
        'msg': msg
    })