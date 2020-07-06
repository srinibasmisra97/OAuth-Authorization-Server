import base64
import re
import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
from passlib.hash import sha256_crypt

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


def validate_email(email):
    """
    This function ensures that the string is a valid email address or not.
    :param email: String to validate.
    :return: Boolean
    """
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    return re.search(regex,email)


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
        return None, None, e


def validate_password(password, hash):
    """
    This function validates if the password hash is the same as the hash provided.
    :param password: Password to hash.
    :param hash: Hash from the db.
    :return: Boolean
    """
    return sha256_crypt.verify(password, hash)


def hash_password(password):
    """
    This function returns the generated hash for the password.
    :param password: String to hash.
    :return: Hash string.
    """
    return sha256_crypt.hash(password)


def check_password_requirement(password):
    """
    This function validates if the password meets the requirements.
    :param password: Password.
    :return: Boolean
    """
    spec_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_']

    if len(password)<10:
        return False, "password length should be more than 10"

    if not any(char.isupper() for char in password):
        return False, "no upper case characters"

    if not any(char.islower() for char in password):
        return False, "no lower case characters"

    if not any(char.isdigit() for char in password):
        return False, "no digits"

    if not any(char in spec_chars for char in password):
        return False, "no special characters"

    return True, "valid"
