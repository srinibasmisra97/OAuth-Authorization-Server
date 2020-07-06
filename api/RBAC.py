from urllib.parse import unquote
from flask import request, jsonify, Response
from flask.blueprints import Blueprint

from Utils.Security import b64decode, validate_email

from Entities.Clients import Clients
from Entities.RBAC import Permission
from Entities.Applications import Application

app_RBAC = Blueprint('RBAC', __name__)


@app_RBAC.route('/api/rbac/permissions', methods=['GET','PUT','POST','DELETE'])
def permissions():
    """
    API for handling permissions related tasks.
    GET to get all the permissions for an api.
    POST to create a new permission.
    PUT to update a permission.
    DELETE to delete a permission.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized
    """
    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] != "Basic":
        return jsonify({
            'success': False,
            'msg': 'unauthorized'
        }), 401

    email = b64decode(authorization.split(" ")[1])
    if not validate_email(email):
        return jsonify({
            'success': False,
            'msg': 'invalid email'
        }), 400

    client = Clients(email=email)
    client_doc = client.get_by_email(email=email)

    if not client_doc:
        return jsonify({
            'success': False,
            'msg': 'email not found'
        })

    if request.method == 'GET':
        if request.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            return jsonify({
                'success': False,
                'msg': 'invalid content type'
            }), 400

        api_id = request.form.get("api")
        if api_id is None:
            return jsonify({
                'success': False,
                'msg': 'api id not provided'
            }), 400

        api_id = request.form.get("api")

        if api_id is None:
            return jsonify({
                'success': False,
                'msg': 'no api id provided'
            }), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        return jsonify({
            'success': False,
            'permissions': app.permissions
        })
    elif request.method == 'POST':
        if request.headers.get("Content-Type") != "application/json":
            return jsonify({
                'success': False,
                'msg': 'invalid content type'
            }), 400

        request_data = request.get_json()
        api_id = request_data.get('api')

        if api_id is None:
            return jsonify({
                'success': False,
                'msg': 'app id not provided'
            }), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        permissions = request_data.get("permissions")
        if permissions is None:
            return jsonify({
                'success': False,
                'msg': 'no permissions provided'
            }), 400

        permission = Permission()
        result, msg = permission.add_many(client=client, application=app, permissions=permissions)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })
    elif request.method == 'DELETE':
        if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
            return jsonify({
                'success': False,
                'msg': 'invalid content type'
            }), 400

        api_id = request.form.get('api')

        if api_id is None:
            return jsonify({
                'success': False,
                'msg': 'no app id provided'
            }), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        value = request.form.get('value')

        if value is None:
            return jsonify({
                'success': False,
                'msg': 'no value provided'
            }), 400

        permission = Permission(value=value)
        result, msg = permission.remove(client=client, application=app)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })
    elif request.method == 'PUT':
        if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
            return jsonify({
                'success': False,
                'msg': 'invalid content type'
            }), 400

        api_id = request.form.get('api')

        if api_id is None:
            return jsonify({
                'success': False,
                'msg': 'no app id provided'
            }), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        old_value = request.args.get('p')
        if old_value is None:
            return jsonify({
                'success': False,
                'msg': 'permission filter not provided'
            }), 400

        old_value = unquote(old_value)
        permission = Permission(value=old_value)
        permission.get(api_id=api_id, permission=old_value)

        if not permission:
            return jsonify({
                'success': False,
                'msg': 'permission not found'
            })

        name = request.form.get('name')
        value = request.form.get('value')

        if name is None:
            result, msg = permission.update_value(client=client, application=app, new_value=value)
        if value is None:
            result, msg = permission.update_name(client=client, application=app, name=name)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })
