import json
from urllib.parse import unquote

from flask import request, jsonify, render_template, redirect
from flask.blueprints import Blueprint

from Utils.Security import b64decode, validate_password, generate_key, generate_jwt, check_scopes
from Utils.Helpers import memcache_connection, list_to_string

from Entities.Applications import Application
from Entities.RBAC import User, Role

app_OAuth = Blueprint('OAuth', __name__)


@app_OAuth.route('/authorize', methods=['GET'])
def authorize():
    """
    OAuth authorize endpoint.
    :return: 200 OK, 503 Service Unavailable, 302 Redirect.
    """
    client_id = request.args.get("client_id")
    response_type = request.args.get("response_type")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    state = request.args.get("state")
    audience = request.args.get("audience")

    if client_id is None or response_type is None or redirect_uri is None or audience is None:
        return render_template('login/invalid_credentials.html'), 503

    if response_type not in ['code', 'token']:
        return render_template('login/invalid_credentials.html'), 503

    app = Application()
    result = app.get_by_key(api_id=audience, key=client_id)
    if not result:
        return render_template('login/invalid_credentials.html'), 503

    if redirect_uri not in app.redirect_uris:
        return render_template('login/invalid_uri.html'), 503

    return render_template('login/index.html', data=request.args, app_name=app.name)


@app_OAuth.route('/signin-password', methods=['POST'])
def signin_password():
    """
    This api is to validate the username and password.
    :return: 200 OK, 400 Bad Request, 301 Permanent Redirect.
    """
    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({
            'success': False,
            'msg': 'invalid content type'
        }), 400

    client_id = request.form.get("client_id")
    audience = request.form.get("audience")

    authorization = str(request.headers.get("Authorization").encode('ascii', 'ignore').decode('utf-8'))
    if authorization.split(" ")[0] != "Basic":
        return jsonify({'success': False, 'msg': 'unauthorized'}), 401

    decoded = b64decode(authorization.split(" ")[1])
    if ":" not in decoded:
        return jsonify({'success': False, 'msg': 'invalid username or password'}), 401

    email = str(decoded).split(":")[0]
    password = str(decoded).split(":")[1]

    app = Application()
    result = app.get_by_key(api_id=audience, key=client_id)
    if not result:
        return render_template('login/invalid_credentials.html'), 503

    user = User(email=email)
    result = user.get_by_email(application=app)

    key = generate_key(10)
    memcache_connection().add(key=key, val=str(user))

    if not result:
        return jsonify({'success': False, 'msg': 'username not found'}), 401

    if not validate_password(password=password, hash=user.password):
        return jsonify({'success': False, 'msg': 'invalid password'}), 401

    return jsonify({'success': True, 'msg': 'logged in', 'session': key})


@app_OAuth.route('/redirect', methods=['GET'])
def redirect_to_uri():
    """
        OAuth authorize endpoint.
        :return: 200 OK, 503 Service Unavailable, 302 Redirect.
        """
    client_id = request.args.get("client_id")
    response_type = request.args.get("response_type")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    state = request.args.get("state")
    audience = request.args.get("audience")
    session = request.args.get("session")

    if client_id is None or response_type is None or redirect_uri is None or audience is None or session is None:
        return render_template('login/invalid_credentials.html'), 503

    if response_type not in ['code', 'token']:
        return render_template('login/invalid_credentials.html'), 503

    app = Application()
    result = app.get_by_key(api_id=audience, key=client_id)
    if not result:
        return render_template('login/invalid_credentials.html'), 503

    if redirect_uri not in app.redirect_uris:
        return render_template('login/invalid_uri.html'), 503

    if scope is not None:
        scope_arr = unquote(scope).split(' ')
    else:
        scope_arr = []

    memcache_client = memcache_connection()
    userinfo = json.loads(memcache_client.get(key=session))
    memcache_client.delete(key=session)

    if response_type == 'code':
        code = generate_key(20)
        memcache_client.add(key=code, val=json.dumps(request.args), time=86400)

        uri = redirect_uri + "?code=" + code
        if scope is not None:
            uri = uri + "&scope=" + scope
        if state is not None:
            uri = uri + "&state=" + state
    elif response_type == 'token':
        payload = {
            'iss': 'auth-server.implicit',
            'sub': client_id + '@auth-server',
            'aud': app.api,
            'gty': 'implicit'
        }

        user = User(email=userinfo['email'])
        user.get_by_email(application=app)

        role = Role(id=user.role)
        role.get(application=app)

        if scope is not None:
            if "profile" in scope:
                payload['name'] = userinfo['name']
                payload['email'] = userinfo['email']
                payload['role'] = userinfo['role']

        payload['scopes'] = list_to_string(check_scopes(requested=scope_arr, allocated=role.permissions)) if scope is not None else ""

        token = generate_jwt(payload=payload, expiry=app.exp)

        uri = redirect_uri + "#" + token

    return redirect(uri)
