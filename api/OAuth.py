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

    code = generate_key(10)
    memcache_connection().add(key=code, val=str(user))

    if not result:
        return jsonify({'success': False, 'msg': 'username not found'}), 401

    if not validate_password(password=password, hash=user.password):
        return jsonify({'success': False, 'msg': 'invalid password'}), 401

    return jsonify({'success': True, 'msg': 'logged in', 'session': code})


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
        data = dict(request.args)
        data['name'] = userinfo['name']
        data['email'] = userinfo['email']
        data['role'] = userinfo['role']
        memcache_client.add(key=code, val=json.dumps(data), time=86400)

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
            'gty': 'implicit',
            'app': app.name
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


@app_OAuth.route('/token', methods=['POST'])
def oauth_token():
    """
    OAuth token endpoint.
    :return: 200 OK, 400 Bad Request, 401 Unauthorized.
    """
    if request.headers.get('Content-Type') != "application/x-www-form-urlencoded":
        return jsonify({'success': False, 'msg': 'invalid content type'}), 400

    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    grant_type = request.form.get("grant_type")
    audience = request.form.get("audience")

    if client_id is None:
        return jsonify({'success': False, 'msg': 'client id missing'}), 401
    if client_secret is None:
        return jsonify({'success': False, 'msg': 'client secret missins'}), 401
    if grant_type is None:
        return jsonify({'success': False, 'msg': 'grant type not provided'}), 400
    if audience is None:
        return jsonify({'success': False, 'msg': 'audience not provided'}), 400

    app = Application()
    result = app.get_by_key_secret(api_id=audience, key=client_id, secret=client_secret)
    if not result:
        return jsonify({'success': False, 'msg': 'invalid credentials'}), 401

    memcache_client = memcache_connection()

    if grant_type == 'authorization_code':
        code = request.form.get("code")
        if code is None:
            return jsonify({'success': False, 'msg': 'missing authorization code'}), 400

        redirect_uri = request.form.get("redirect_uri")
        if redirect_uri is None:
            return jsonify({'success': False, 'msg': 'redirect uri missing'}), 400

        cached_data = memcache_client.get(key=code)
        if cached_data is None:
            return jsonify({'success': False, 'msg': 'invalid code'}), 401
        data = json.loads(cached_data)

        if redirect_uri != data['redirect_uri']:
            return jsonify({'success': False, 'msg': 'invalid redirect uri'}), 401

        user = User(email=data['email'])
        result = user.get_by_email(application=app)
        if not result:
            return jsonify({'success': False, 'msg': 'user not found'}), 401

        role = Role(id=user.role)
        role.get(application=app)

        payload = {
            'iss': 'auth-server.authorization-code',
            'sub': client_id + '@auth-server',
            'aud': app.api,
            'gty': 'authorization_code',
            'app': app.name
        }
        if 'scope' in data:
            scopes = data['scope']
            scopes_arr = str(scopes).split(" ")
        else:
            scopes = ""
            scopes_arr = []

        if "profile" in scopes:
            payload['name'] = data['name']
            payload['email'] = data['email']
            payload['role'] = data['role']

        payload['scopes'] = list_to_string(check_scopes(requested=scopes_arr, allocated=role.permissions)) if scopes is not None else ""

        token = generate_jwt(payload=payload, expiry=app.exp)
        memcache_client.delete(key=code)
        return jsonify({'token': token, 'scopes': scopes, 'type': 'Bearer', 'expiry': app.exp, 'grant_type': grant_type})
    elif grant_type == 'client_credentials':
        payload = {
            'iss': 'auth-server.authorization-code',
            'sub': client_id + '@auth-server',
            'aud': app.api,
            'gty': 'client_credentials',
            'app': app.name
        }
        token = generate_jwt(payload=payload, expiry=app.exp)
        return jsonify({'token': token, 'type': 'Bearer', 'expiry': app.exp, 'grant_type': grant_type})
    else:
        return jsonify({'success': False, 'msg': 'invalid grant type'}), 400