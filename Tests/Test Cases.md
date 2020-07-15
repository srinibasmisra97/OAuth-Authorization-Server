# Test Cases
### Sign Up
#### http://localhost:5000/signup

* Valid request method check.
* Content Type check.
* Authorization header checks:
    * No Authorization header check.
    * Invalid Authorization header check:
        * Basic Authorization header check.
        * Invalid username:password string.
* First Name and Last Name not provided check.
* Invalid email check.
* Check password requirement check.
* Invalid first name and last name check.
* Success message check.

### Sign In
#### http://localhost:5000/signin

* Valid request method check.
* Authorization header checks:
    * No Authorization header check.
    * Invalid Authorization header check:
        * Basic Authorization header check.
        * Invalid username:password string.
* User not found check.
* Invalid password check.
* Successful sign in check.
* Response Authorization header check:
    * Bearer Authorization header check.
    * Verify JWT Token check.
    * JWT Token content check:
        1. iss: auth-server.signin.token
        2. aud: admin.apis
        3. sub in payload.
        4. email, first_name, last_name check.

### Registering an App
#### http://localhost:5000/register

* Valid request method check.
* Authorization header checks:
    * No authorization header.
    * Invalid authorization header checks:
        * Bearer token check.
        * Invalid token check.
    * User present check.
    * User email verification.
* Content-Type check.
* Parameters check:
    * App name not provided check.
    * App API ID not provided check.
    * Grant types check.
* App successful register check.
* Response header checks:
    * Authorization header present.
    * Basic Authorization header check.
    * Base64 client_id:client_secret message check.

### Generating New Key Secret Pair and Deleting Key
#### http://localhost:5000/key

* Valid request method check.
* Authorization header checks:
    * No authorization header.
    * Invalid authorization header checks:
        * Bearer token check.
        * Invalid token check.
    * User present check.
    * User email verification.
* Content-Type check.
* Parameters check:
    * App API ID not provided check.
    * Grant types check.
* Generate new key pair.
* Response header checks:
    * Authorization header present.
    * Basic Authorization header check.
    * Base64 client_id:client_secret message check.
* Delete key.

### Update Allowed Redirect URIs
#### http://localhost:5000/uris

* Valid request method check.
* Authorization header checks:
    * No authorization header.
    * Invalid authorization header checks:
        * Bearer token check.
        * Invalid token check.
    * User present check.
    * User email verification.
* Content-Type check.
* Parameters check:
    * App API ID not provided check.
    * URIs not provided check.
* App not found check.
* Successful update check.

### Update Allowed Grant Types
#### http://localhost:5000/gtypes

* Valid request method check.
* Authorization header checks:
    * No authorization header.
    * Invalid authorization header checks:
        * Bearer token check.
        * Invalid token check.
    * User present check.
    * User email verification.
* Content-Type check.
* Parameters check:
    * App API ID not provided check.
    * Grant Types not provided check.
* App not found check.
* Successful update check.