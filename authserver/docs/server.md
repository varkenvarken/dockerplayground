# Table of Contents

* [server](#server)
* [server.server](#server.server)
  * [number](#server.server.number)
  * [getvar](#server.server.getvar)
  * [getfile](#server.server.getfile)
  * [newpassword](#server.server.newpassword)
  * [checkpassword](#server.server.checkpassword)
  * [allowed\_password](#server.server.allowed_password)
  * [ParameterSet](#server.server.ParameterSet)
    * [\_\_init\_\_](#server.server.ParameterSet.__init__)
    * [check](#server.server.ParameterSet.check)
  * [alchemyencoder](#server.server.alchemyencoder)
  * [User](#server.server.User)
  * [Session](#server.server.Session)
  * [PendingUser](#server.server.PendingUser)
  * [PasswordReset](#server.server.PasswordReset)
  * [max\_body](#server.server.max_body)
  * [LoginResource](#server.server.LoginResource)
    * [on\_post](#server.server.LoginResource.on_post)
  * [RegisterResource](#server.server.RegisterResource)
    * [on\_post](#server.server.RegisterResource.on_post)
  * [ForgotPasswordResource](#server.server.ForgotPasswordResource)
  * [VerifySessionResource](#server.server.VerifySessionResource)
  * [LogoutResource](#server.server.LogoutResource)
  * [ChoosePasswordResource](#server.server.ChoosePasswordResource)
  * [StatsResource](#server.server.StatsResource)
  * [ConfirmRegistrationResource](#server.server.ConfirmRegistrationResource)
  * [ConfirmForgotPasswordResource](#server.server.ConfirmForgotPasswordResource)
  * [fetch\_admin\_params](#server.server.fetch_admin_params)
  * [add\_superuser](#server.server.add_superuser)

<a name="server"></a>
# server

The server package implements an authentication server.

It is a WSGI app implemented in falcon and exposes an app variable that can be called from any WSGI server, like gunicorn.

A typical invocation is

    gunicorn -b 0.0.0.0:8005 server:app

On import a sqlite database is initialized and logging is started.

For more information see [the GitHub repo](https://github.com/varkenvarken/dockerplayground/tree/master/authserver)

The following attributes will be initialized to the values defined in the corresponding environment variables

__Attributes__


- `DEBUGLEVEL`: can be CRITICAL, ERROR, SUCCESS, INFO, DEBUG, TRACE. Defaults to DEBUG
- `DATABASE_FILE`: path to databse file, default to `user.db
- `DATABASE_BACKOFF`: number of seconds to ait between database connection retries, defaults to 1, doubles every retry.
- `DATABASE_RETRIES`: number of times to retry a database connection. Defaults to 3.

<a name="server.server"></a>
# server.server

This module handles the http requests related to user and session management.

It also provides utility functions to initialize the database and admin user.

The attributes defined here contain values retrieved from their corresponding environment variables.

__Attributes__


- `DOMAIN`: e.g. yourdomain.org
- `APPLICATION`: e.g. /books
- `LOGINSCREEN`: e.g. /books/login.html
- `CONFIRMREGISTRATION`: e.g. https://server.yourdomain.org/auth/confirmregistration
- `RESETPASSWORD`: e.g. https://server.yourdomain.org/auth/resetpassword
- `WEBSITE`: e.g. Book Collection
- `SOFTTIMEOUT`: soft session limit in minutes, default 30
- `HARDTIMEOUT`: hard session limit in minutes, default 480
- `PWRESETTIMEOUT`: maximum number of minutes before a passwordreset must be confirmed, default 60
- `REGISTERTIMEOUT`: maximum number of minutes before a new registration must be confirmed, default 60
- `EMAILTEMPLATE_FORGOTPASSWORD`: file location of password reset email, default `mailtemplates/passwordreset.mail`
- `EMAILTEMPLATE_REGISTER`: file location of registration email, default `mailtemplates/registration.mail`
- `ADMIN_USER_FILE`: filename of file containing super user username (valid email address)
- `ADMIN_USER`: username (valid email address) of super user, will override ADMIN_USER_FILE
- `ADMIN_PASSWORD_FILE`: filename of file containing super user password in plaintext
- `ADMIN_PASSWORD`: super user password in plaintext, will override ADMIN_PASSWORD_FILE

<a name="server.server.number"></a>
#### number

```python
number(variable, default)
```

Return the integer in the environment variable.

__Arguments__


- __variable__ (`str`):    the name of the environment variable
- __default__ (`int`):     the default value to return if variable is not defined

__Returns__


An integer value.

<a name="server.server.getvar"></a>
#### getvar

```python
getvar(variable, default='<unknown>')
```

Return the value of the environment variable.

__Arguments__


- __variable__ (`str`):    the name of the environment variable
- __default__ (`str`):     the default value to return if variable is not defined

__Returns__


A string.

<a name="server.server.getfile"></a>
#### getfile

```python
getfile(variable, defaultfilename, default='Hi {name}, click {link}, Regards {website}')
```

Return the contents of the file specified in the environment variable.

__Arguments__


- __variable__ (`str`):           the name of the environment variable
- __defaultfilename__ (`str`):    the filename to use if the variable is not defined
- __default__ (`str`):            the string to return if the file couldn't be found

the default contains the following placeholders

- {name}    the full name of the user
- {link}    a confirmation link to click
- {website} the name of the application/website

__Returns__


A string.

<a name="server.server.newpassword"></a>
#### newpassword

```python
newpassword(password)
```

Return a cryptographic hash of password as a string of hex digits.

The password is salted with 16 random bytes.
The salt is prepended as 32 hex digits to the returned hash.

__Arguments__


- __password__ (`str`):  the password to hash.

__Returns__


A string consisting of 32 + 64 hexadecimal characters.

<a name="server.server.checkpassword"></a>
#### checkpassword

```python
checkpassword(password, reference)
```

Compare a plaintext password to a hashed reference.

The reference is a string of hex digits, the first 32 being the salt.

<a name="server.server.allowed_password"></a>
#### allowed\_password

```python
allowed_password(s)
```

Check if a password meets the complexity criteria:

- between 8 and 64 characters,
- contain at least 1 lowercase, 1 uppercase, 1 digit and 1 special character
- it may not contain characters outside those classes
- character classes *are* unicode aware

<a name="server.server.ParameterSet"></a>
## ParameterSet Objects

```python
class ParameterSet()
```

Defines allowable input parameters for a POST or GET request.

__Attributes__


- `__init__(self, specs={})`:   creates a ParameterSet instance based on a dictionary of parameters
- `check(self, params)`: verify that a dictionary of params conforms to the defined requirements

<a name="server.server.ParameterSet.__init__"></a>
#### \_\_init\_\_

```python
 | __init__(specs={})
```

Creates a ParameterSet instance based on a dictionary of parameters.

__Arguments__


- __specs__ (`dict`): specifies a mapping name --> (ex, maxlength)

    `name` is a case sensitive name of an allowed input parameter

    `ex` is either a string, a regular expression or a callable that specifies the validity of a value.

    `maxlength` is an integer that specifies the maximum length of a parameter value

    If `ex` is a string it is converted to a regular expression.

    If `ex` is a callable it should return a boolean indicating the validity of a value.

<a name="server.server.ParameterSet.check"></a>
#### check

```python
 | check(params)
```

Return true if all params are all allowed.

__Arguments__


- __params__ (`dict`): is a mapping name --> value,  where name and value are strings

    Each value should match the requirements specfied for 'name'.

    If `params` contains extra parameters or it is missing items it is considered invalid.

<a name="server.server.alchemyencoder"></a>
#### alchemyencoder

```python
alchemyencoder(obj)
```

A json encoder for SQLAlchemy declarative_base objects, date and Decimal objects.

`Base` objects are returned a `dict` object with a key for each column.
A column with a name equal to `password` is _not_ included.
If a Base object has a `user` column, an extra key `email` is added that contains `user.email`.


`date` objects are returned as an isoformat string.

`Decimal` objects are returned as a float.

__Arguments__


- __obj__ (`object`): an object to decode

__Returns__


A `dict`, `str`, `float` or `None`.

Like all default encoders for json it returns objects which are then encoded to json strings by the main encoder.

__Example__


```
import json

jsonstring = json.dumps(someobject, default=alchemyencoder)
```

<a name="server.server.User"></a>
## User Objects

```python
class User(Base)
```

ORM representation of a User.

__Attributes__


- `id(int)`: primary key
- `email(str)`: user name (a valid email address)
- `password(str)`: hashed password
- `name(str)`: full name
- `superuser(bool)`: role, true if superuser
- `created(datetime)`: timestamp
- `active(bool)`: true if user account is enabled
- `attempts(int)`: number of failed login attemtps
- `accessed(datetime)`: timestamp of last access
- `locked(datetime)`: timestamp of user lockout

<a name="server.server.Session"></a>
## Session Objects

```python
class Session(Base)
```

ORM representation of a Session.

__Attributes__


- `id(str)`: primary key holds a guid
- `created(datetime)`: timestamp
- `softlimit(datetime)`: timestamp, session must show activity before this time to be renewed
- `hardlimit(datetime)`: timestamp, after this time the session will be removed regardless
- `userid(int)`: foreign key to User, on cascade delete is on
- `user`: ORM link to User


This session will be deleted if the corresponding user is deleted.

<a name="server.server.PendingUser"></a>
## PendingUser Objects

```python
class PendingUser(Base)
```

ORM representation of a PendingUser (a newly registered user awaiting confirmation).

__Attributes__


- `id(str)`: primary key holds a guid
- `email(str)`: user name (a valid email address)
- `password(str)`: hashed password
- `name(str)`: full name
- `created(datetime)`: timestamp
- `expires(datetime)`: timestamp, after this time the session will be removed regardless

<a name="server.server.PasswordReset"></a>
## PasswordReset Objects

```python
class PasswordReset(Base)
```

ORM representation of a PasswordReset event awaiting confirmation.

__Attributes__


- `id(str)`: primary key holds a guid
- `created(datetime)`: timestamp
- `expires(datetime)`: timestamp, after this time the session will be removed regardless
- `userid(int)`: foreign key to User, on cascade delete is on
- `user`: ORM link to User


This PasswordReset will be deleted if the corresponding user is deleted.

<a name="server.server.max_body"></a>
#### max\_body

```python
max_body(limit)
```

A falcon before hook to limit size of request body.

__Arguments__


- __limit__ (`int`): maximum size in bytes of the request body.

__Raises__


- `falcon.HTTPPayloadTooLarge`: when the body of the request exceeds `limit`.

__Returns__


a hook function.

<a name="server.server.LoginResource"></a>
## LoginResource Objects

```python
class LoginResource()
```

Routing endpoint that serves the action of a login form.

This resource only defines an `on_post()` method.

<a name="server.server.LoginResource.on_post"></a>
#### on\_post

```python
 | @falcon.before(max_body(1024))
 | on_post(req, resp)
```

Handle a logon POST request.

__Arguments__

- __req__: the request
- __resp__: the response

__Returns__

None

The method expects its input as www-formencoded parameters in the request body.
On success it will set the Location header to APPLICATION and return a session cookie.
On failure it will set the Location header to LOGINSCREEN.
It will always set the response status to falcon.HTTP_303.

__Parameters__


- __- email__: the username of the user (a valid email address)
- __- password__: the password
- __- login__: the literal text `Login`

Typically these parameters would correspond to input fields in an HTML form and a submit button wit a `name=Login` attribute.

<a name="server.server.RegisterResource"></a>
## RegisterResource Objects

```python
class RegisterResource()
```

Routing endpoint that serves the action of a registration form.

This resource only defines an `on_post()` method.

<a name="server.server.RegisterResource.on_post"></a>
#### on\_post

```python
 | @falcon.before(max_body(1024))
 | on_post(req, resp)
```

Handle a register POST request.

__Arguments__

- __req__: the request
- __resp__: the response

__Returns__

None

The method expects its input as www-formencoded parameters in the request body.
On success it will create a pending user request and send an email with a confirmation link.
On failure it will do nothing.
It will always set the Location header to LOGINSCREEN.
It will always set the response status to falcon.HTTP_303.

__Parameters__


- __- email__: the username of the user (a valid email address)
- __- name__: the full name of the user
- __- password__: the password ( 8 >= length <= 64, must contain at lease 1 lowercase, 1 uppercase, 1 digit and 1 special char.
- __- password2__: must be identical to the password parameter
- __- login__: the literal text `Register`

Typically these parameters would correspond to input fields in an HTML form and a submit button wit a `name=Register` attribute.

<a name="server.server.ForgotPasswordResource"></a>
## ForgotPasswordResource Objects

```python
class ForgotPasswordResource()
```

Routing endpoint that serves the action of a forgot password form.

This resource only defines an `on_post()` method.

<a name="server.server.VerifySessionResource"></a>
## VerifySessionResource Objects

```python
class VerifySessionResource()
```

Routing endpoint that serves as the internal endpoint to verify the existence of a valid session.

This resource only defines an `on_post()` method.

<a name="server.server.LogoutResource"></a>
## LogoutResource Objects

```python
class LogoutResource()
```

Routing endpoint that serves the action of a logout form.

This resource only defines an `on_post()` method.

<a name="server.server.ChoosePasswordResource"></a>
## ChoosePasswordResource Objects

```python
class ChoosePasswordResource()
```

Routing endpoint that serves the action of a choose new password form.

This resource only defines an `on_post()` method.

<a name="server.server.StatsResource"></a>
## StatsResource Objects

```python
class StatsResource()
```

Routing endpoint that serves the REST endpoint for user information overviews.

This resource only defines an `on_post()` method.

<a name="server.server.ConfirmRegistrationResource"></a>
## ConfirmRegistrationResource Objects

```python
class ConfirmRegistrationResource()
```

Routing endpoint that serves the registration confirmation link.

This resource only defines an `on_get()` method.

<a name="server.server.ConfirmForgotPasswordResource"></a>
## ConfirmForgotPasswordResource Objects

```python
class ConfirmForgotPasswordResource()
```

Routing endpoint that serves the password reset confirmation link.

This resource only defines an `on_get()` method.

<a name="server.server.fetch_admin_params"></a>
#### fetch\_admin\_params

```python
fetch_admin_params()
```

Get admin variables from file or environment.

enviroment variables overrule variables in files.

__Returns__

tuple(admin_user, admin_password)

__Module level attributes referenced__


- ADMIN_USER_FILE: filename of file containing super user username (valid email address)
- ADMIN_USER: username (valid email address) of super user, will override ADMIN_USER_FILE
- ADMIN_PASSWORD_FILE: filename of file containing super user password in plaintext
- ADMIN_PASSWORD: super user password in plaintext, will override ADMIN_PASSWORD_FILE

<a name="server.server.add_superuser"></a>
#### add\_superuser

```python
add_superuser()
```

Add superuser account to User table.

Will remove any user account with the same name along with any associated session.

