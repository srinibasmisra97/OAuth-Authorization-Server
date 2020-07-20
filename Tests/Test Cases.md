# Test Cases
### Sign Up
#### http://localhost:5000/signup

* Valid request method.
* Content Type.
* Authorization header s:
    * No Authorization header.
    * Invalid Authorization header:
        * Basic Authorization header.
        * Invalid username:password string.
* First Name and Last Name not provided.
* Invalid email.
* Check password requirement.
* Invalid first name and last name.
* Success message.

### Sign In
#### http://localhost:5000/signin

* Valid request method.
* Authorization header s:
    * No Authorization header.
    * Invalid Authorization header:
        * Basic Authorization header.
        * Invalid username:password string.
* User not found.
* Invalid password.
* Successful sign in.
* Response Authorization header:
    * Bearer Authorization header.
    * Verify JWT Token.
    * JWT Token content:
        1. iss: auth-server.signin.token
        2. aud: admin.apis
        3. sub in payload.
        4. email, first_name, last_name.

### Registering an App
#### http://localhost:5000/register

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * App name not provided.
    * App API ID not provided.
    * Grant types.
* App successful register.
* Response header s:
    * Authorization header present.
    * Basic Authorization header.
    * Base64 client_id:client_secret message.

### Generating New Key Secret Pair and Deleting Key
#### http://localhost:5000/key

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * App API ID not provided.
    * Grant types.
* Generate new key pair.
* Response header s:
    * Authorization header present.
    * Basic Authorization header.
    * Base64 client_id:client_secret message.
* Delete key.

### Update Allowed Redirect URIs
#### http://localhost:5000/uris

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * App API ID not provided.
    * URIs not provided.
* App not found.
* Successful update.

### Update Allowed Grant Types
#### http://localhost:5000/gtypes

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * App API ID not provided.
    * Grant Types not provided.
* App not found.
* Successful update.

### RBAC Permissions
#### http://localhost:5000/api/rbac/permissions

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * GET Request:
        * App API ID not provided.
        * App not found.
    * POST Request:
        * App API ID not provided.
        * App not found.
        * Permissions not provided.
        * Name not present.
        * Value not present.
    * DELETE Request:
        * App API ID not provided.
        * App not found.
        * Value not provided.
    * PUT Request:
        * App API ID not provided.
        * App not found.
        * Permission filter not provided.
        * Name not provided.
        * Value not provided.
* Successful operation:
    * Add
    * Get
    * Delete
    * Update

### RBAC Roles
#### http://localhost:5000/api/rbac/roles

* Valid request method.
* Authorization header s:
    * No authorization header.
    * Invalid authorization header s:
        * Bearer token.
        * Invalid token.
    * User present.
    * User email verification.
* Content-Type.
* Parameters:
    * GET Request:
        * App API ID not provided.
        * App not found.
    * POST Request:
        * App API ID not provided.
        * App not found.
        * Permissions not provided.
        * Name not present.
        * ID not present.
        * Permissions not present.
    * DELETE Request:
        * App API ID not provided.
        * App not found.
        * Role ID not provided.
        * Role not found.
    * PUT Request:
        * App API ID not provided.
        * App not found.
        * Role ID not provided.
        * Role not found.
* Successful operation:
    * Add
    * Get
    * Delete
    * Update