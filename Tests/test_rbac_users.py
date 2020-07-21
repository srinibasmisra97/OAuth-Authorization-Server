import base64
import configparser
import jwcrypto.jwk as jwk
import os
import pytest
import python_jwt as jwt
import requests
import datetime
import secrets

private_key = jwk.JWK.from_pem(open('keys/private.pem', 'rb').read())
public_key = jwk.JWK.from_pem(open('keys/public.pem', 'rb').read())


def b64encode(message):
    """
    This function encodes a string to base64.
    :param message: String to encode.
    :return: Base64 encoded string.
    """
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def b64decode(base64_message):
    """
    This function decodes a base64 string.
    :param base64_message: Base64 message to decode.
    :return: Decoded string.
    """
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message


def generate_jwt(payload, expiry):
    """
    This function generates a JWT token.
    :param payload: JSON Object containing payload data.
    :param expiry: Expiry time for the token. In minutes.
    :return: String JWT Token.
    """
    return jwt.generate_jwt(payload, private_key, 'RS256', datetime.timedelta(minutes=expiry))


def verify_jwt(token):
    """
    This function verifies a jwt token.
    :param token: String JWT Token
    :return: header, claims
    """
    try:
        header, claims = jwt.verify_jwt(token, public_key, ['RS256'])
        return header, claims, None
    except Exception as e:
        return None, None, str(e)


CONFIG_FILEPATH = os.path.join(os.getcwd(), "testSetup.cfg")
CONFIG_ENV = os.environ.get('CONFIG_ENV') or 'TEST'

cfg = configparser.RawConfigParser()
cfg.read(CONFIG_FILEPATH)

AUTH_TOKEN_ENDPOINT = str(cfg.get(CONFIG_ENV, "URL")) + "/signin"
URL = str(cfg.get(CONFIG_ENV, "URL")) + "/api/rbac/users"
EMAIL = str(cfg.get(CONFIG_ENV, "EMAIL"))
PASSWORD = str(cfg.get(CONFIG_ENV, "PASSWORD"))
FIRST_NAME = str(cfg.get(CONFIG_ENV, "FIRST_NAME"))
LAST_NAME = str(cfg.get(CONFIG_ENV, "LAST_NAME"))
APP_NAME = str(cfg.get(CONFIG_ENV, "APP_NAME"))
APP_API = str(cfg.get(CONFIG_ENV, "APP_API"))
APP_GRANT_TYPE = [uri.strip() for uri in str(cfg.get(CONFIG_ENV, "APP_GRANT_TYPES")).split(",")]
APP_REDIRECT_URIS = [gty.strip() for gty in str(cfg.get(CONFIG_ENV, "APP_REDIRECT_URIS")).split(",")]
RBAC_PERMISSION_NAMES = [perm.strip() for perm in str(cfg.get(CONFIG_ENV, "RBAC_PERMISSION_NAMES")).split(",")]
RBAC_PERMISSION_VALUES = [val.strip() for val in str(cfg.get(CONFIG_ENV, "RBAC_PERMISSION_VALUES")).split(",")]
RBAC_ROLE_NAME = str(cfg.get(CONFIG_ENV, "RBAC_ROLE_NAME"))
RBAC_ROLE_ID = str(cfg.get(CONFIG_ENV, "RBAC_ROLE_ID"))
RBAC_USER_NAME = str(cfg.get(CONFIG_ENV, "RBAC_USER_NAME"))
RBAC_USER_EMAIL = str(cfg.get(CONFIG_ENV, "RBAC_USER_EMAIL"))
RBAC_USER_PWD = str(cfg.get(CONFIG_ENV, "RBAC_USER_PWD"))

if len(RBAC_PERMISSION_VALUES) == 0 or len(RBAC_PERMISSION_NAMES) == 0:
    print("PLEASE ADD PERMISSIONS TO CONFIG")
    exit(0)


@pytest.mark.skip
def get_token():
    """
    Hits the token endpoint and returns a token.
    """
    response = requests.post(AUTH_TOKEN_ENDPOINT, headers={'Authorization': 'Basic ' + b64encode(EMAIL + ":" + PASSWORD)})
    return response.headers.get("Authorization").split(" ")[1]


@pytest.mark.rbac_users
def test_rbac_users_auth_header():
    """
    No authorization header.
    """
    response = requests.put(URL)
    assert response.status_code == 401, "Invalid status code for no auth header check"
    assert not response.json()['success'], "Invalid response for no auth header"
    """
    Bearer authorization header check.
    """
    response = requests.put(URL, headers={'Authorization': 'Basic abcdef'})
    assert response.status_code == 400, "Invalid status code for bearer auth header check"
    assert not response.json()['success'], "Invalid response for bearer auth header check"
    """
    Invalid bearer token check.
    """
    response = requests.put(URL, headers={'Authorization': 'Bearer abcdef'})
    assert response.status_code == 401, "Invalid status code for invalid bearer token check"
    """
    User not present check.
    """
    temp_token = generate_jwt({
        'iss': 'auth-server.signin.token',
        'aud': 'admin.apis',
        'sub': secrets.token_hex(12),
        'email': EMAIL,
        'first_name': FIRST_NAME,
        'last_name': LAST_NAME
    }, expiry=1)
    response = requests.put(URL, headers={'Authorization': 'Bearer ' + temp_token})
    assert response.status_code == 401, "Invalid status code for user not present check"
    """
    User email check.
    """
    headers, claims, err = verify_jwt(get_token())
    claims['email'] = "test@example.com"
    response = requests.put(URL, headers={'Authorization': 'Bearer ' + generate_jwt(payload=claims, expiry=1)})
    assert response.status_code == 401, "Invalid status code for invalid email check"
    assert response.json()['msg'] == "invalid email", "Invalid response message for invalid email check"


@pytest.mark.run(order=6)
@pytest.mark.rbac_users
def test_rbac_users_content_type():
    """
    application/x-www-form-urlencoded check for GET
    """
    HEADERS = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + get_token()}
    response = requests.get(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - GET request"
    """
        application/json check for POST
    """
    response = requests.post(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - POST request"
    """
        application/json check for DELETE
    """
    response = requests.delete(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - DELETE request"
    """
        application/json check for PUT
    """
    response = requests.put(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - PUT request"


@pytest.mark.run(order=15)
@pytest.mark.rbac_users
def test_rbac_users_parameters():
    """ GET request check """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.get(url=URL, headers=headers)
    assert response.status_code == 400, "Invalid status code for api id not present - GET request"
    response = requests.get(url=URL, headers=headers, data={'api': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for app not found - GET request"
    """ POST request """
    response = requests.post(url=URL, headers=headers, data={})
    assert response.status_code == 400, "Invalid status code for api id not present - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for app not found - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API})
    assert response.status_code == 400, "Invalid status code for email not provided - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': secrets.token_hex(8), 'password': secrets.token_hex(8), 'name': secrets.token_hex(8), 'role':secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for invalid email provided - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL})
    assert response.status_code == 400, "Invalid status code for password not provided - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD})
    assert response.status_code == 400, "Invalid status code for name not provided - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': RBAC_USER_NAME})
    assert response.status_code == 400, "Invalid status code for role id not provided - POST request"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': secrets.token_hex(8), 'role': RBAC_ROLE_ID})
    assert not response.json()['success'], "Invalid response message for invalid name"
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': RBAC_USER_NAME, 'role': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for role not found"
    """ DELETE request """
    response = requests.delete(url=URL, headers=headers)
    assert response.status_code == 400, "Invalid status code for api id not provided - DELETE request"
    response = requests.delete(url=URL, headers=headers, data={'api': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for app not found - DELETE request"
    response = requests.delete(url=URL, headers=headers, data={'api': APP_API})
    assert response.status_code == 400, "Invalid status code for email not provided - DELETE request"
    response = requests.delete(url=URL, headers=headers, data={'api': APP_API, 'email': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for email not found"
    """ PUT request """
    response = requests.put(url=URL, headers=headers, json={})
    assert response.status_code == 400, "Invalid status code for api id not present - PUT request"
    response = requests.put(url=URL, headers=headers, json={'api': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for app not found - PUT request"
    response = requests.put(url=URL, headers=headers, json={'api': APP_API})
    assert response.status_code == 400, "Invalid status code for email not provided - PUT request"
    response = requests.put(url=URL, headers=headers, json={'api': APP_API, 'email': secrets.token_hex(8)})
    assert not response.json()['success'], "Invalid response message for email not found"


@pytest.mark.run(order=26)
@pytest.mark.rbac_users
def test_rbac_users_add():
    """
    Test case to add user
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': RBAC_USER_NAME, 'role': RBAC_ROLE_ID})
    assert response.status_code == 200, "Error while adding user"


@pytest.mark.run(order=27)
@pytest.mark.rbac_users
def test_rbac_users_add_existing():
    """
    Test case to add existing user
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': RBAC_USER_NAME, 'role': RBAC_ROLE_ID})
    assert not response.json()['success'], "Invalid response message for adding existing user"


@pytest.mark.run(order=28)
@pytest.mark.rbac_users
def test_rbac_users_get():
    """
    Test case to get user
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.get(url=URL, headers=headers, data={'api': APP_API})
    assert response.status_code == 200, "Error while getting users"
    same = True
    for user in response.json()['users']:
        if user['email'] != RBAC_USER_EMAIL or user['name'] != RBAC_USER_NAME or user['role'] != RBAC_ROLE_ID:
            same = False
    assert same, "User not correct"


@pytest.mark.run(order=29)
@pytest.mark.rbac_users
def test_rbac_users_delete():
    """
    Test case to delete user
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.delete(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL})
    assert response.status_code == 200, "Error while deleting user"
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    response = requests.post(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'password': RBAC_USER_PWD, 'name': RBAC_USER_NAME, 'role': RBAC_ROLE_ID})


@pytest.mark.run(order=30)
@pytest.mark.rbac_users
def test_rbac_users_update():
    """
    Test case to update a user
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.put(url=URL, headers=headers, data={'api': APP_API, 'email': RBAC_USER_EMAIL, 'role': RBAC_ROLE_ID})
    print(response.json())
    assert response.status_code == 200, "Error while updating user"
