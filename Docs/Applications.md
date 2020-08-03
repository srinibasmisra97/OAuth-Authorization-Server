# Applications

Applications are the apps that clients can create/register which can serve as the Login page and the OAuth flow.

## Data Model
```json
{
  "name": "<App Name>",
  "api": "<API Identifier>",
  "owner": "<Client ObjectID>",
  "permissions": [
    {
      "name": "<Permission Name>",
      "value": "<Permission Value>"
    },
    {
      "name": "<Permission Name>",
      "value": "<Permission Value>"
    }
  ],
  "roles": [
    {
      "name": "<Role Name>",
      "id": "<Role Identifier>",
      "permissions": ["<Permission Value>", "<Permission Value>", "<Permission Value>"]
    }
  ],
  "users": [
    {
      "email": "<Member Email>",
      "password": "<Hashed Password>",
      "first_name": "<First Name>",
      "last_name": "<Last Name>",
      "role": "<Role Id>"
    },
    {
      "email": "<Member Email>",
      "password": "<Hashed Password>",
      "first_name": "<First Name>",
      "last_name": "<Last Name>",
      "role": "<Role Id>"
    }
  ],
  "exp": 15,
  "creds": [
    {
      "key": "<Client Key>",
      "secret": "<Client Secret>"
    },
    {
      "key": "<Client Key>",
      "secret": "<Client Secret>"
    }
  ]
}
```

## APIs

### Register (POST /register)

This API is used to register/create an app.

**Content-Type**: application/x-www-form-urlencoded

#### Headers:
1. Access Token as Bearer token.
2. Content-Type: application/x-www-form-urlencoded.

#### Parameters:
1. name: Name of the application. (Req.)
2. api: Audience or a unique id for the Application. (Req.)
3. exp: Token expiry amount.
4. grant_types: Grant types allowed for the application.
5. redirect_uris: Redirect URIs allowed for the application.

#### Example:
```bash
curl --location --request POST 'http://localhost:5000/register' \
--header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbi5hcGlzIiwiZW1haWwiOiJzcmluaWJhcy5taXNyYTk3QGdtYWlsLmNvbSIsImV4cCI6MTU5NjI4NjE1NywiZmlyc3RfbmFtZSI6IlNyaW5pYmFzIiwiaWF0IjoxNTk2Mjg0MzU3LCJpc3MiOiJhdXRoLXNlcnZlci5zaWduaW4udG9rZW4iLCJqdGkiOiJUSlpLNDFFRHpld2Z2N0Qwc2JQaGpRIiwibGFzdF9uYW1lIjoiTWlzcmEiLCJuYmYiOjE1OTYyODQzNTcsInN1YiI6IjVmMjU1ZGMxZDcwNjY1YWM3NWQ2MWYxNyJ9.Cl3kNLOFmzC-pTghtlhRb8GInZT6f2I2lVn-RzWJDFl1lK0M5nDewKy-50lNlIPtVjmEeKiPqNvz9UTAMSCmc6SCIoALG8ZuJskMKex6mpZ9ehozwvw7Lj8ZySFpLiRQCGZQZ3xbT88CIyWKA-Urb_AQEsG0ArwVBDzZFZhgYtLPyiTKbgFOhYc6pmnT3-sKbV0QL6xc1l5Wg0d5leArCqzCpm2L2T90ZqdyK_MyrXSLZMpXijWgoSgohCYsH29uDqz_gn-NPT7yUyRRBY-ozBW5WtVvys-ww7KiPzj0gcJ4hNKxW2VL2_V9fyri_wDWwSjzXvC2zDMI5T2FKYsPbQ' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'name=Auth Server Application' \
--data-urlencode 'api=app://srini-app-to-delete' \
--data-urlencode 'exp=1' \
--data-urlencode 'grant_types=implicit, authorization_code, client_credentials' \
--data-urlencode 'redirect_uris=https://www.example.com'
```

#### Responses:

##### 200 OK
200 is returned on successful creation of an application. Response header contains a basic authentication header consiting of client_id:client_secret.

##### 401 Unauthorized
401 is returned for the following scenarios:
1. No authorization header.
2. User not found.
3. Invalid email.

##### 400 Bad Request
400 is returned under the following scenarios:
1. Invalid authorization token.
2. Invalid content type.
3. Too many parameters.
4. Required parameters not passed.

### New Key (PUT /key)

This API is used to add a new set of key and secret pair.

**Content-Type**: application/x-www-form-urlencoded

#### Headers:
1. Access Token as Bearer token.
2. Content-Type: application/x-www-form-urlencoded.

#### Parameters:
1. api: Audience or a unique id for the Application. (Req.)

#### Reponses:

##### 200 OK
If all credentials are valid. Response header contains a basic authentication header consiting of client_id:client_secret.

##### 401 Unauthorized
401 is returned for the following scenarios:
1. No authorization header.
2. User not found.
3. Invalid email.

##### 400 Bad Request
400 is returned under the following scenarios:
1. Invalid authorization token.
2. Invalid content type.
3. Too many parameters.
4. Required parameters not passed.

### Delete Key (DELETE /key)

This API is used to delete a set of key and secret pair.

**Content-Type**: application/x-www-form-urlencoded

#### Headers:
1. Access Token as Bearer token.
2. Content-Type: application/x-www-form-urlencoded.

#### Parameters:
1. api: Audience or a unique id for the Application. (Req.)
2. key: Client ID to delete. (Req.)

#### Reponses:

##### 200 OK
If all credentials are valid.

##### 401 Unauthorized
401 is returned for the following scenarios:
1. No authorization header.
2. User not found.
3. Invalid email.

##### 400 Bad Request
400 is returned under the following scenarios:
1. Invalid authorization token.
2. Invalid content type.
3. Too many parameters.
4. Required parameters not passed.

### Delete App (DELETE /app)

This API is used to delete an application.

**Content-Type**: application/x-www-form-urlencoded

#### Headers:
1. Access Token as Bearer token.
2. Content-Type: application/x-www-form-urlencoded.

#### Parameters:
1. api: Audience or a unique id for the Application. (Req.)
2. key: Client ID to delete. (Req.)

#### Reponses:

##### 200 OK
If all credentials are valid.

##### 401 Unauthorized
401 is returned for the following scenarios:
1. No authorization header.
2. User not found.
3. Invalid email.

##### 400 Bad Request
400 is returned under the following scenarios:
1. Invalid authorization token.
2. Invalid content type.
3. Too many parameters.
4. Required parameters not passed.