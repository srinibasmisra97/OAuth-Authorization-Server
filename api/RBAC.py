from urllib.parse import unquote
from flask import request, jsonify
from flask.blueprints import Blueprint
from bson.objectid import ObjectId

from Utils.Security import b64decode, validate_password, verify_jwt, check_password_requirement, validate_email, hash_password

from Entities.Clients import Clients
from Entities.RBAC import Permission, Role, User
from Entities.Applications import Application

app_RBAC = Blueprint('RBAC', __name__)


@app_RBAC.before_request
def before_request():
    """
        Before request email and password validation.
    """
    if request.headers.get("Authorization") is None:
        return jsonify({'success': False, 'msg': 'unauthorized'}), 401
    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] == 'Bearer':
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

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        return jsonify({
            'success': True,
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

        for perm in permissions:
            if "name" not in perm:
                return jsonify({'success': False, 'msg': 'no name provided'}), 400
            if "value" not in perm:
                return jsonify({'success': False, 'msg': 'no value provided'}), 400

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
        permission.get(application=app, permission=old_value)

        if not permission:
            return jsonify({
                'success': False,
                'msg': 'permission not found'
            })

        name = request.form.get('name')
        value = request.form.get('value')

        if name is None and value is None:
            return jsonify({
                'success': False,
                'msg': 'either name or value should be provided'
            }), 400

        if name is None:
            result, msg = permission.update_value(client=client, application=app, new_value=value)
        if value is None:
            result, msg = permission.update_name(client=client, application=app, name=name)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })


@app_RBAC.route('/api/rbac/roles', methods=['GET', 'POST', 'PUT', 'DELETE'])
def roles():
    """
    API for handling roles related tasks.
    GET for getting all the roles defined for the application.
    POST to add roles to the application.
    PUT to update roles of the application.
    DELETE to delete roles for the application.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized.
    """
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
            'roles': app.roles
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

        roles = request_data.get("roles")
        if roles is None:
            return jsonify({
                'success': False,
                'msg': 'no roles provided'
            }), 400

        existing = app.permissions

        for role in roles:
            if "name" not in role:
                return jsonify({'success': False, 'msg': 'no name provided for role'}), 400
            if "id" not in role:
                return jsonify({'success': False, 'msg': 'no id provided for role'}), 400
            if "permissions" not in role:
                return jsonify({'success': False, 'msg': 'no permissions provided for role'}), 400

            found = False
            for permission in role['permissions']:
                for ep in existing:
                    if permission == ep['value']:
                        found = True
                        break
                if not found:
                    return jsonify({'success': False, 'msg': 'permission ' + permission + ' not defined'}), 400

        role = Role()
        result, msg = role.add_many(client=client, application=app, roles=roles)

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

        role_id = request.form.get('role')

        if role_id is None:
            return jsonify({
                'success': False,
                'msg': 'no id provided'
            }), 400

        role = Role(id=role_id)
        result = role.get(client=client, application=app, role_id=role_id)

        if not result:
            return jsonify({'success': False, 'msg': 'role not found'})

        result, msg = role.delete(client=client, application=app)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })
    elif request.method == 'PUT':
        if request.headers.get("Content-Type") != "application/json":
            return jsonify({'success': False, 'msg': 'invalid content type'})

        request_data = request.get_json()

        api_id = request_data.get("api")
        role_id = request_data.get("role")
        name = request_data.get("name")
        permissions = request_data.get("permissions")

        if api_id is None:
            return jsonify({'success': False, 'msg': 'no app id provided'}), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({'success': False, 'msg': 'app not found'})

        role = Role(id=role_id)
        result = role.get(client=client, application=app)

        if not result:
            return jsonify({'success': False, 'msg': 'role not found'})

        result_permissions = result_name = msg_permissions = msg_name = None
        if permissions is not None:
            existing = app.permissions
            found = False
            for permission in permissions:
                for ep in existing:
                    if permission == ep['value']:
                        found = True
                        break
                if not found:
                    return jsonify({'success': False, 'msg': 'permission ' + permission + ' not defined'}), 400
            result_permissions, msg_permissions = role.update_permissions(client=client, application=app, permissions=permissions)
        if name is not None:
            result_name, msg_name = role.update_name(client=client, application=app, name=name)

        return jsonify({
            'success': bool(result_permissions or result_name),
            'msg': 'updated' if bool(result_name or result_permissions) else 'failed'
        })


@app_RBAC.route('/api/rbac/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
def users():
    """
    This API handles all application users related tasks.
    GET to get all users.
    POST to add new users.
    PUT to update users.
    DELETE to remove users.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized
    """
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
        result = app.get_by_api_id(api_id=api_id, projection={"password":0, "users.password": 0})

        if not result:
            return jsonify({
                'success': False,
                'msg': 'app not found'
            })

        return jsonify({
            'success': True,
            'roles': app.users
        })
    elif request.method == 'POST':
        if request.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            return jsonify({
                'success': False,
                'msg': 'invalid content type'
            }), 400

        api_id = request.form.get('api')

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

        user_email = request.form.get("email")
        user_password = request.form.get("password")
        user_name = request.form.get("name")
        user_role = request.form.get("role")

        if user_email is None:
            return jsonify({'success': False, 'msg': 'no email provided'}),400
        if user_password is None:
            return jsonify({'success': False, 'msg': 'no password provided'}), 400
        if user_name is None:
            return jsonify({'success': False, 'msg': 'no name provided'}), 400
        if user_role is None:
            return jsonify({'success': False, 'msg': 'no role provided'}), 400

        if not validate_email(email=user_email):
            return jsonify({'success': False, 'msg': 'invalid email'})

        found = False
        for eu in app.users:
            if user_email == eu['email']:
                found = True
                break
        if found:
            return jsonify({'success': False, 'msg': 'existing user'})

        result, msg = check_password_requirement(password=user_password)
        if not result:
            return jsonify({'success': False, 'msg': msg})

        if not str(user_name).isalpha():
            if " " not in str(user_name):
                return jsonify({'success': False, 'msg': 'unknown character in name'})

        found = False
        for role in app.roles:
            if user_role == role['id']:
                found = True
                break
        if not found:
            return jsonify({'success': False, 'msg': 'role not defined'})

        user = User(email=user_email, password=hash_password(password=user_password), name=user_name, role=user_role)
        result, msg = user.add(client=client, application=app)

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

        user_email = request.form.get('email')

        if user_email is None:
            return jsonify({
                'success': False,
                'msg': 'no email provided'
            }), 400

        user = User(email=user_email)
        result = user.get_by_email(client=client, application=app, email=user_email)

        if not result:
            return jsonify({'success': False, 'msg': 'user not found'})

        result, msg = user.remove(client=client, application=app)

        return jsonify({
            'success': True if result else False,
            'msg': msg
        })
    elif request.method == 'PUT':
        if request.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            return jsonify({'success': False, 'msg': 'invalid content type'}), 400

        api_id = request.form.get("api")
        user_email = request.form.get("email")
        user_name = request.form.get("name")
        user_role = request.form.get("role")
        password = request.form.get("password")

        if api_id is None:
            return jsonify({'success': False, 'msg': 'no app id provided'}), 400

        app = Application(api=api_id)
        result = app.get_by_api_id(api_id=api_id)

        if not result:
            return jsonify({'success': False, 'msg': 'app not found'})

        if user_email is None:
            return jsonify({'success': False, 'msg': 'email not provided'}), 400

        user = User(email=user_email)
        if not user.get_by_email(client=client, application=app):
            return jsonify({'success': False, 'msg': 'user not found'})

        result_role = result_name = result_password = msg_role = msg_name = msg_password = None
        if user_role is not None:
            found = False
            for er in app.roles:
                if user_role == er['id']:
                    found = True
                    break
            if found:
                return jsonify({'success': False, 'msg': 'role not defined'})
            result_role, msg_role = user.update_role(client=client, application=app, role=user_role)
        if user_name is not None:
            result_name, msg_name = user.update_name(client=client, application=app, name=user_name)
        if password is not None:
            if not check_password_requirement(password=password):
                return jsonify({'success': False, 'msg': 'password does not meet requirements'})
            result_password, msg_password = user.update_password(client=client, application=app, password=hash_password(password=password))

        return jsonify({
            'success': bool(result_role or result_name or result_password),
            'msg': 'updated' if (result_role or result_name or result_password) else 'failed'
        })