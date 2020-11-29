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
  * [fetch\_admin\_params](#server.server.fetch_admin_params)

<a name="server"></a>
# server

The server package implements an authentication server.

It is a WSGI app implemented in falcon and exposes an app variable that can be called from any WSGI server, like gunicorn.

A typical invocation is

    gunicorn -b 0.0.0.0:8005 server:app

On import a sqlite database is initialized and logging is started.

For more information see [the GitHub repo](https://github.com/varkenvarken/dockerplayground/tree/master/authserver)

<a name="server.server"></a>
# server.server

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

Defines allowable input parameters for a POST request.

<a name="server.server.ParameterSet.__init__"></a>
#### \_\_init\_\_

```python
 | __init__(specs={})
```

specs is a dict name --> (ex, maxlength)

name is a case sentive name of an allowed input parameter
ex is either a string, a regular expression or a callable
maxlength is an integer

if ex is a string it is converted to a regular expression.
if ex is a callable it should return a boolean indicating the validity of a value.

<a name="server.server.ParameterSet.check"></a>
#### check

```python
 | check(params)
```

return true if the params are all allowed.

params is a dict name --> value where name and value are strings

if params contains extra parameters or it is missing items it is considered invalid.

<a name="server.server.alchemyencoder"></a>
#### alchemyencoder

```python
alchemyencoder(obj)
```

A json encoder for ORM objects, date and Decimal objects.

like all default encoders for json it returns strings which are then encoded to json.

<a name="server.server.fetch_admin_params"></a>
#### fetch\_admin\_params

```python
fetch_admin_params()
```

Get admin variables from file or environment.

enviroment variables overrule variables in files.

