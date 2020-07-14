import base64
import configparser
import jwcrypto.jwk as jwk
import os
import pytest
import python_jwt as jwt
import requests

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

URL = str(cfg.get(CONFIG_ENV, "URL")) + "/signin"
EMAIL = str(cfg.get(CONFIG_ENV, "EMAIL"))
PASSWORD = str(cfg.get(CONFIG_ENV, "PASSWORD"))
FIRST_NAME = str(cfg.get(CONFIG_ENV, "FIRST_NAME"))
LAST_NAME = str(cfg.get(CONFIG_ENV, "LAST_NAME"))
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + b64encode(EMAIL + ":" + PASSWORD)}


@pytest.mark.signin
def test_signin_request_method():
    """
    Check for valid request method only.
    """
    response = requests.get(URL)
    assert response.status_code == 405, "Invalid status code for GET request"
    response = requests.put(URL)
    assert response.status_code == 405, "Invalid status code for PUT request"
    response = requests.delete(URL)
    assert response.status_code == 405, "Invalid status code for DELETE request"


@pytest.mark.signin
def test_signin_auth_header():
    """
    No authorization header check.
    """
    response = requests.post(URL)
    assert response.status_code == 401, "Invalid status code for no Authorization header"
    assert not response.json()['success'], "Invalid response for no Authorization header"
    """
    Basic Authorization header check.
    """
    response = requests.post(URL, headers={'Authorization': 'Bearer abcdef'})
    assert response.status_code == 401, "Invalid status code for Bearer Authorization header"
    assert not response.json()['success'], "Invalid response for Authorization Bearer token"
    """
    Invalid username:password string check.
    """
    response = requests.post(URL, headers={'Authorization': 'Basic ' + b64encode(EMAIL)})
    assert response.status_code == 400, "Invalid status code for invalid username:password string"
    assert not response.json()['success'], "Invalid status code for invalid username:password string"


@pytest.mark.run(order=3)
@pytest.mark.signin
def test_signin_user_not_found():
    """
    User not found check.
    """
    response = requests.post(URL, headers={'Authorization': 'Basic ' + b64encode("test@example.com:testpassword!1")})
    assert response.status_code == 200, "Error in getting token"
    assert response.json()['msg'] == "please sign up first", "Error in getting token"


@pytest.mark.run(order=4)
@pytest.mark.signin
def test_signin_incorrect_password():
    """
    Incorrect password.
    """
    response = requests.post(URL, headers={'Authorization': 'Basic ' + b64encode(EMAIL + ":testpassword!1")})
    print({'Authorization': 'Basic ' + b64encode(EMAIL + ":testpassword!1")})
    print(response.status_code)
    print(response.headers)
    print(response.json())
    assert response.status_code == 401, "Error in getting token"
    assert response.json()['msg'] == "invalid password", "Error in getting token"


@pytest.mark.run(order=5)
@pytest.mark.signin
def test_signin_token():
    """
    Sign In procedure.
    """
    response = requests.post(URL, headers=HEADERS)
    assert response.status_code == 200, "Error in getting token"
    assert response.headers.get("Authorization") is not None, "No authorization header in response"
    assert "Bearer" in response.headers.get("Authorization"), "Invalid authorization header"
    headers, claims, err = verify_jwt(response.headers.get("Authorization").split(" ")[1])
    assert headers is not None, "Invalid access token: " + err
    assert claims['iss'] == "auth-server.signin.token", "Invalid issuer claim"
    assert claims['aud'] == "admin.apis", "Invalid audience claim"
    assert "sub" in claims, "sub not in claims"
    assert "email" in claims, "email not in claims"
    assert "first_name" in claims, "first_name not in claims"
    assert "last_name" in claims, "last_name not in claims"
