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
URL = str(cfg.get(CONFIG_ENV, "URL")) + "/key"
EMAIL = str(cfg.get(CONFIG_ENV, "EMAIL"))
PASSWORD = str(cfg.get(CONFIG_ENV, "PASSWORD"))
FIRST_NAME = str(cfg.get(CONFIG_ENV, "FIRST_NAME"))
LAST_NAME = str(cfg.get(CONFIG_ENV, "LAST_NAME"))
APP_NAME = str(cfg.get(CONFIG_ENV, "APP_NAME"))
APP_API = str(cfg.get(CONFIG_ENV, "APP_API"))
APP_GRANT_TYPE = str(cfg.get(CONFIG_ENV, "APP_GRANT_TYPES"))
APP_REDIRECT_URIS = str(cfg.get(CONFIG_ENV, "APP_REDIRECT_URIS"))
CLIENT_ID = None
CLIENT_SECRET = None


@pytest.mark.skip
def get_token():
    """
    Hits the token endpoint and returns a token.
    """
    response = requests.post(AUTH_TOKEN_ENDPOINT, headers={'Authorization': 'Basic ' + b64encode(EMAIL + ":" + PASSWORD)})
    return response.headers.get("Authorization").split(" ")[1]


@pytest.mark.app_key
def test_app_key_request_method():
    """
    Check for valid request method only.
    """
    response = requests.get(URL)
    assert response.status_code == 405, "Invalid status code for GET request"
    response = requests.post(URL)
    assert response.status_code == 405, "Invalid status code for POST request"


@pytest.mark.app_key
def test_app_key_auth_header():
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
    assert response.json()['msg'] == "user not found", "Invalid response message for user not present check"
    """
    User email check.
    """
    headers, claims, err = verify_jwt(get_token())
    claims['email'] = "test@example.com"
    response = requests.put(URL, headers={'Authorization': 'Bearer ' + generate_jwt(payload=claims, expiry=1)})
    assert response.status_code == 401, "Invalid status code for invalid email check"
    assert response.json()['msg'] == "invalid email", "Invalid response message for invalid email check"


@pytest.mark.run(order=6)
@pytest.mark.app_key
def test_app_key_content_type():
    """
    Invalid Content-Type check.
    """
    HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.put(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - PUT request"
    assert not response.json()['success'], "Invalid response for application/json content-type - PUT request"
    response = requests.delete(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for application/json content-type - DELETE request"
    assert not response.json()['success'], "Invalid response for application/json content-type - DELETE request"


@pytest.mark.run(order=10)
@pytest.mark.app_key
def test_app_key_parameters():
    """
    No API id provided check.
    """
    HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.put(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for no api id provided - PUT request"
    response = requests.delete(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for no api id provided - DELETE request"


@pytest.mark.run(order=11)
@pytest.mark.app_key
def test_app_key_add_key():
    """
    Generate new key secret pair.
    """
    global CLIENT_ID, CLIENT_SECRET
    HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.put(URL, headers=HEADERS, data={'api': APP_API})
    assert response.status_code == 200, "Error in generating new key secret pair"
    """
        Response Authorization header check.
    """
    assert response.headers.get("Authorization") is not None, "No authorization header present in response"
    """
    Response Basic Authorization header check.
    """
    assert response.headers.get("Authorization").split(" ")[0] == "Basic", "Invalid authorization header in response"
    """
    Client ID, Client Secret check.
    """
    decoded = b64decode(response.headers.get("Authorization").split(" ")[1])
    assert ":" in decoded, "Invalid client_id:client_secret basic authentication header"
    CLIENT_ID = decoded.split(":")[0]
    CLIENT_SECRET = decoded.split(":")[1]


@pytest.mark.run(order=12)
@pytest.mark.app_key
def test_app_key_delete_key():
    """
    Delete a key
    """
    global CLIENT_ID
    HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + get_token()}
    response = requests.delete(URL, headers=HEADERS, data={'api': APP_API, 'key': CLIENT_ID})
    assert response.status_code == 200, "Error while deleting client id"
