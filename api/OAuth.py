import json

from flask import request, jsonify, render_template, redirect
from flask.blueprints import Blueprint

from Utils.Security import b64decode, validate_password, generate_key
from Utils.Memcache import memcache_connection

from Entities.Applications import Application
from Entities.RBAC import User

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
    response_type = request.form.get("response_type")
    redirect_uri = request.form.get("redirect_uri")
    scope = request.form.get("scope")
    state = request.form.get("state")
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

    if not result:
        return jsonify({'success': False, 'msg': 'username not found'}), 401

    if not validate_password(password=password, hash=user.password):
        return jsonify({'success': False, 'msg': 'invalid password'}), 401

    return jsonify({'success': True, 'msg': 'logged in'})


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

    if client_id is None or response_type is None or redirect_uri is None or audience is None:
        return render_template('login/invalid_credentials.html'), 503

    app = Application()
    result = app.get_by_key(api_id=audience, key=client_id)
    if not result:
        return render_template('login/invalid_credentials.html'), 503

    if redirect_uri not in app.redirect_uris:
        return render_template('login/invalid_uri.html'), 503

    code = generate_key(20)
    memcache_connection().add(key=code, val=json.dumps(request.args), time=86400)

    uri = redirect_uri + "?code=" + code
    if scope is not None:
        uri = uri + "&scope=" + scope
    if state is not None:
        uri = uri + "&state=" + state

    return redirect(uri)
