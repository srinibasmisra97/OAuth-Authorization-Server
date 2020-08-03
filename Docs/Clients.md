# Clients

Clients are the overall users that can signup, and create applications which can be used to setup an OAuth flow.

## Data Model
```json
{
  "first_name": "<First Name>",
  "last_name": "<Last Name>",
  "email": "<Email>",
  "apps": [
    "ObjectID",
    "ObjectID",
    "ObjectID"
  ]
}
```

## APIs

### Signup (POST /signup)

This API can be used to create a new client.

**Content-Type**: application/x-www-form-urlencoded

#### Headers:
1. Username:Password as Basic Authentication header.
2. Content-Type: x-www-form-urlencoded.

#### Parameters:
1. first_name: First name of the user/client.
2. last_name: Last name of the user/client.

#### Example:
```bash
curl --location --request POST 'http://localhost:5000/signup' \
--header 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'first_name=Srinibas' \
--data-urlencode 'last_name=Misra'
```

#### Responses:

##### 200 OK
200 is returned when the user signup process is completed successfully.

##### 400 Bad Request
400 is returned for scenarios such as:
1. Invalid content type
2. Invalid basic authentication header.
3. Too many parameters
4. No first name provided.
5. No last name provided.

##### 401 Unauthorized
401 is returned if the Authorization header is not provided.

### Signin (POST /signup)

This API is used to get an access token for clients/user.

#### Parameters:
1. username:password as Basic Authentication header.

#### Example:
```bash
curl --location --request POST 'http://localhost:5000/signin' \
--header 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK'
```

#### APIs

##### 200 OK
200 is returned if the user credentials are valid. And the response authorization header contains the acess token as a Bearer token.

##### 400 Bad Request
400 is returned if the username/password is missing.

##### 401 Unauthorized
401 is returned on multiple scenarios:
1. No authorization header.
2. Invalid password.