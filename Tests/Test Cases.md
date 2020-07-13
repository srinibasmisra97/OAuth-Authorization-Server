#Test Cases
###Sign Up
####http://locatalhost:5000/signup

* Valid request method check.
* Content Type check.
* No Authorization header check.
* Invalid Authorization header check:
    * Basic Authorization header check.
    * Invalid username:password string.
* Too many parameters check.
* First Name and Last Name not provided check.
* Invalid email check.
* Check password requirement check.
* Invalid first name and last name check.
* Success message check.

###Sign In
####http://localhost:5000/signin

* Valid request method check.
* No Authorization header check.
* Invalid Authorization header check:
    * basic Authorization header check.
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