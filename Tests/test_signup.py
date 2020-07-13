import requests, pytest, base64, configparser, os


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


CONFIG_FILEPATH = os.path.join(os.getcwd(), "testSetup.cfg")
CONFIG_ENV = os.environ.get('CONFIG_ENV') or 'TEST'

cfg = configparser.RawConfigParser()
cfg.read(CONFIG_FILEPATH)

URL = str(cfg.get(CONFIG_ENV, "URL")) + "/signup"
EMAIL = str(cfg.get(CONFIG_ENV, "EMAIL"))
PASSWORD = str(cfg.get(CONFIG_ENV, "PASSWORD"))
FIRST_NAME = str(cfg.get(CONFIG_ENV, "FIRST_NAME"))
LAST_NAME = str(cfg.get(CONFIG_ENV, "LAST_NAME"))
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + b64encode(EMAIL + ":" + PASSWORD)}


@pytest.mark.signup
def test_signup_request_method():
    """
    Check for valid request method only.
    """
    response = requests.get(URL)
    assert response.status_code == 405, "Invalid status code for GET request"
    response = requests.put(URL)
    assert response.status_code == 405, "Invalid status code for PUT request"
    response = requests.delete(URL)
    assert response.status_code == 405, "Invalid status code for DELETE request"


@pytest.mark.signup
def test_signup_content_type():
    """
    Invalid Content-Type check.
    """
    response = requests.post(URL, headers={'Content-Type': 'application/json'})
    assert response.status_code == 400, "Invalid status code for application/json content-type"
    assert not response.json()['success'], "Invalid response for application/json content-type"


@pytest.mark.signup
def test_signup_auth_header():
    """
    No authorization header check.
    """
    response = requests.post(URL, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert response.status_code == 401, "Invalid status code for application/json content-type"
    assert not response.json()['success'], "Invalid response for no Authorization header"
    """
    Basic Authorization header check.
    """
    response = requests.post(URL, headers={'Content-Type': 'application/x-www-form-urlencoded',
                                           'Authorization': 'Bearer abcdef'})
    assert response.status_code == 401, "Invalid status code for Bearer Authorization header"
    assert not response.json()['success'], "Invalid response for Authorization Bearer token"
    """
    Invalid username:password string check.
    """
    response = requests.post(URL, headers={'Content-Type': 'application/x-www-form-urlencoded',
                                           'Authorization': 'Basic ' + b64encode(EMAIL)})
    assert response.status_code == 400, "Invalid status code for invalid username:password string"
    assert not response.json()['success'], "Invalid status code for invalid username:password string"


@pytest.mark.signup
def test_signup_parameters():
    """
    First Name not provided check.
    """
    response = requests.post(URL, headers=HEADERS)
    assert response.status_code == 400, "Invalid status code for no first name provided"
    assert response.json()['msg'] == "no first name provided", "Invalid response message for first name not provided"
    """
    Last Name not provided check.
    """
    response = requests.post(URL, headers=HEADERS, data={'first_name': 'Srinibas'})
    assert response.status_code == 400, "Invalid status code for no last name provided"
    assert response.json()['msg'] == "no last name provided", "Invalid response message for last name not provided"
    """
    Invalid email check.
    """
    headers1 = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + b64encode("test@example:testexample")}
    response = requests.post(URL, headers=headers1, data={'first_name': 'Testfirstname', 'last_name': 'Testlastname'})
    assert response.status_code == 400, "Invalid status code for invalid email"
    assert response.json()['msg'] == "invalid email", "Invalid response message for invalid email"
    """
    Invalid password check.
    """
    headers1 = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + b64encode("test@example.com:test")}
    response = requests.post(URL, headers=headers1, data={'first_name': 'Testfirstname', 'last_name': 'Testlastname'})
    assert not response.json()['success'], "invalid response message for password requirements not met"
    """
    Invalid First name.
    """
    response = requests.post(URL, headers=HEADERS, data={'first_name': 'Test123', 'last_name': 'Test123'})
    assert response.status_code == 400, "Invalid status code for invalid first name"
    assert response.json()['msg'] == "invalid first name", "Invalid response message for invalid first name provided"
    """
    Invalid Last name.
    """
    response = requests.post(URL, headers=HEADERS, data={'first_name': 'Testfirstname', 'last_name': 'Test123'})
    assert response.status_code == 400, "Invalid status code for invalid last name"
    assert response.json()['msg'] == "invalid last name", "Invalid response message for invalid last name provided"


@pytest.mark.signup
def test_signup_signup():
    """
    Successful sign up.
    """
    response = requests.post(URL, headers=HEADERS, data={'first_name': FIRST_NAME, 'last_name': LAST_NAME})
    assert response.status_code == 200, "Error in user sign up"
    assert response.json()['msg'] == "success", "Error in user sign up"


@pytest.mark.signup
def test_signup_existing():
    """
    Existing user not allowed check.
    """
    response = requests.post(URL, headers=HEADERS, data={'first_name': FIRST_NAME, 'last_name': LAST_NAME})
    assert response.status_code == 200, "Error in user sign up"
    assert response.json()['msg'] == "existing", "Error in user sign up"
