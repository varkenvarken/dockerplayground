#  server.py, part of the authserver package
#
#  part of https://github.com/varkenvarken/dockerplayground
#
#  (c) 2020 Michel Anders (varkenvarken)
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
"""
This module handles the http requests related to user and session management.

It also provides utility functions to initialize the database and admin user.

The attributes listed below configure the authserver and are initialized from
environment variables with the same name.

Additional attributes are defined at the package level (in :mod:`server`) and in :mod:`.smtp` .

Attributes:

- :attr:`DOMAIN`
- :attr:`APPLICATION`
- :attr:`LOGINSCREEN`
- :attr:`CONFIRMREGISTRATION`
- :attr:`RESETPASSWORD`
- :attr:`WEBSITE`
- :attr:`SOFTTIMEOUT`
- :attr:`HARDTIMEOUT`
- :attr:`PWRESETTIMEOUT`
- :attr:`REGISTERTIMEOUT`
- :attr:`EMAILTEMPLATE_FORGOTPASSWORD`
- :attr:`EMAILTEMPLATE_REGISTER`

The following environment variables define credentials but are not present in the module as attributes.

- `ADMIN_USER_FILE` point to a file containing admin user name.
- `ADMIN_USER` admin user name, overrides `ADMIN_USER_FILE`
- `ADMIN_PASSWORD_FILE` point to a file containing admin password.
- `ADMIN_PASSWORD` admin password, overrides `ADMIN_PASSWORD_FILE`

"""

import usercustomize

from datetime import datetime, date, timedelta
from uuid import uuid4 as guid
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from os import urandom
import os
from smtp import fetch_smtp_params, mail
from decimal import Decimal
import json
from time import sleep

import falcon

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import event, create_engine, ForeignKey, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.engine import Engine

from loguru import logger

from regex import compile  # we use an alternative regular expression library here to support unicode classes like \p{L}
from regex.regex import Pattern

logger.info(usercustomize.coverage)


def number(variable, default):
    """
    Return the integer in the environment variable.

    Arguments:
        variable(str):    the name of the environment variable
        default(int):     the default value to return if variable is not defined

    Returns:
        An integer value.
    """
    if variable in os.environ:
        return int(os.environ[variable])
    return int(default)


def getvar(variable, default='<unknown>'):
    """
    Return the value of the environment variable.

    Arguments:
        variable(str):    the name of the environment variable
        default(str):     the default value to return if variable is not defined

    Returns:
        A string.
    """
    if variable in os.environ:
        return os.environ[variable]
    return default


def getfile(variable, defaultfilename, default='Hi {name}, click {link}, Regards {website}'):
    """
    Return the contents of the file specified in the environment variable.

    Arguments:
        variable(str):           the name of the environment variable
        defaultfilename(str):    the filename to use if the variable is not defined
        default(str):            the string to return if the file couldn't be found

    The default contains the following placeholders that can be used in the actual files as well

    - {name}    the full name of the user
    - {link}    a confirmation link to click
    - {website} the name of the application/website

    Returns:
        A string.
    """
    filename = defaultfilename
    text = default
    if variable in os.environ:
        filename = os.environ[variable]
    try:
        with open(filename) as f:
            text = "".join(f.readlines())
    except FileNotFoundError:
        logger.error(f"could not open {filename}")
        text = default
    return text


DOMAIN              = getvar('DOMAIN')
"""Domain to be used in session cookie, e.g. `yourdomain.org` """

APPLICATION         = getvar('APPLICATION')
"""Redirect locations for successful logon, e.g. `/books`"""

LOGINSCREEN         = getvar('LOGINSCREEN')
"""Location of login screen, e.g. `/books/login.html`"""

CONFIRMREGISTRATION = getvar('CONFIRMREGISTRATION')
"""Base url in email registration confirmation, e.g. ``https://server.yourdomain.org/auth/confirmregistration``"""

RESETPASSWORD       = getvar('RESETPASSWORD')
"""Base url in password reset request confirmation, e.g. ``https://server.yourdomain.org/auth/resetpassword``"""

WEBSITE             = getvar('WEBSITE')
"""The name of the app/website, e.g. `Book Collection`"""

SOFTTIMEOUT = number('SOFTTIMEOUT', 30)
"""Session soft limit in minutes"""

HARDTIMEOUT = number('HARDTIMEOUT', 8 * 60)
"""Session hard limit in minutes"""

PWRESETTIMEOUT = number('PWRESETTIMEOUT', 1 * 60)
"""Password reset request confirmation limit in minutes"""

REGISTERTIMEOUT = number('REGISTERTIMEOUT', 1 * 60)
"""Registration confirmation limit in minutes"""

EMAILTEMPLATE_FORGOTPASSWORD = getfile('EMAILTEMPLATE_FORGOTPASSWORD', 'mailtemplates/passwordreset.mail')
"""
File containing email template for password reset confirmation email

See :func:`getfile` for allowed template variables inside the text.
"""

EMAILTEMPLATE_REGISTER = getfile('EMAILTEMPLATE_REGISTER', 'mailtemplates/registration.mail')
"""
File containing email template for registration confirmation email

See :func:`getfile` for allowed template variables inside the text.
"""

SESSIONID_pattern   = compile(r"[01-9a-f]{32}")
"""Legal pattern for a session id and confirmation ids"""

# TODO expand password patterns to full unicode
PASSWORD_lower      = compile(r"[a-z]")
"""These characters are considered lowercase in passwords"""

PASSWORD_upper      = compile(r"[A-Z]")
"""These characters are considered uppercase in passwords"""

PASSWORD_digit      = compile(r"[01-9]")
"""These characters are considered digits in passwords"""

PASSWORD_special    = compile(r"[ !|@#$%^&*()\-_.,<>?/\\{}\[\]]")
"""These characters are considered special in passwords"""


def newpassword(password):
    """
    Return a cryptographic hash of password as a string of hex digits.

    The password is salted with 16 random bytes.
    The salt is prepended as 32 hex digits to the returned hash.

    Arguments:
        password(str):  the password to hash.

    Returns:
        A string consisting of 32 + 64 hexadecimal characters.
    """
    salt = urandom(16)
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + dk.hex()


def checkpassword(password, reference):
    """
    Compare a plaintext password to a hashed reference.

    The reference is a string of hex digits, the first 32 being the salt.
    """
    salt = bytes.fromhex(reference[:32])
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return compare_digest(salt.hex() + dk.hex(), reference)


def allowed_password(s):
    """
    Check if a password meets the complexity criteria:

    - between 8 and 64 characters,
    - contain at least 1 lowercase, 1 uppercase, 1 digit and 1 special character
    - it may not contain characters outside those classes
    - character classes _are_ unicode aware
    """
    if len(s) > 64 or len(s) < 8:
        return False
    nlower = len(PASSWORD_lower.findall(s))
    nupper = len(PASSWORD_upper.findall(s))
    ndigit = len(PASSWORD_digit.findall(s))
    nspecial = len(PASSWORD_special.findall(s))
    if nlower < 1 or nupper < 1 or ndigit < 1 or nspecial < 1:
        return False
    if nlower + nupper + ndigit + nspecial != len(s):
        return False
    return True


class ParameterSet:

    """
    Defines allowable input parameters for a POST or GET request.
    """

    def __init__(self, specs={}):
        """
        Creates a ParameterSet instance based on a dictionary of parameters.

        Arguments:
            specs(dict): specifies a mapping name --> (ex, maxlength)
              `name` is a case sensitive name of an allowed input parameter

              `ex` is either a string, a regular expression or a callable that specifies the validity of a value.

              `maxlength` is an integer that specifies the maximum length of a parameter value

              If `ex` is a string it is converted to a regular expression.

              If `ex` is a callable it should return a boolean indicating the validity of a value.
        """
        self.specs = {}
        for k, v in specs.items():
            r, length = v
            if isinstance(r, str):
                self.specs[k] = compile(r), length
            else:
                self.specs[k] = r, length
        self.keys = set(self.specs.keys())

    def check(self, params):
        """
        Return true if all params are all allowed.

        Arguments:
            params(dict): is a mapping name --> value,  where name and value are strings
              Each value should match the requirements specified for 'name'.

              If `params` contains extra parameters or it is missing items it is considered invalid.
        """
        logger.debug(f'params {params}')
        if set(params.keys()) == self.keys:  # all input names should be present
            for k, v in params.items():
                r, length = self.specs[k]
                if len(v) > length:  # values that are too long are invalid
                    logger.debug(f'too long {k}:{v}')
                    return False
                elif isinstance(r, Pattern):
                    if not bool(r.fullmatch(v)):
                        logger.debug(f'no match {k}:{v}  re:{r.pattern}')
                        return False
                elif not r(v):
                    logger.debug(f'not {r.__name__} {k}: {v}')
                    return False
            return True
        logger.debug(f'keynames do not match: {params.keys()}, required {self.keys}')
        return False


Base = declarative_base()


def alchemyencoder(obj):
    """
    A JSON encoder for SQLAlchemy :func:`declarative_base` objects, :class:`date` and :class:`Decimal` objects.

    :class:`Base` objects are returned as :class:`dict` object with a key for each column.
    A column with a name equal to `password` is _not_ included.
    If a Base object has a `user` column, an extra key `email` is added that contains `user.email`.


    :class:`date` objects are returned as an isoformat string.

    :class:`Decimal` objects are returned as a float.

    Arguments:
        obj(object): an object to decode

    Returns:
        A :class:`dict`, :class:`str`, :class:`float` or `None`.

    Like all default encoders for json it returns objects which are then encoded to json strings by the main encoder.

    an example::

        import json

        jsonstring = json.dumps(someobject, default=alchemyencoder)
    """
    if isinstance(obj, Base):
        d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name != 'password'}  # passwords *never* leave the system, not even encrypted
        if hasattr(obj, 'user'):
            d['email'] = obj.user.email
        return d
    elif isinstance(obj, date):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)


class User(Base):
    """
    ORM representation of a User.
    """

    __tablename__ = 'user'

    id          = Column(Integer, primary_key=True)
    """Primary key"""

    email       = Column(String(100, collation='NOCASE'), unique=True)
    """user name (a valid email address)"""

    password    = Column(String(100))
    """hashed password"""

    name        = Column(String(100))
    """full name"""

    superuser   = Column(Boolean(), default=False)
    """role, true if superuser"""

    created     = Column(DateTime(), default=datetime.now())
    """timestamp"""

    active      = Column(Boolean(), default=True)
    """true if user account is enabled"""

    attempts    = Column(Integer, default=0)
    """number of failed login attempts"""

    accessed    = Column(DateTime(), default=datetime.now())
    """timestamp of last access"""

    locked      = Column(DateTime(), default=datetime.now())
    """timestamp of user lockout"""


class Session(Base):
    """
    ORM representation of a Session.

    Any session will be deleted if the corresponding user is deleted.
    """

    __tablename__ = 'session'

    id          = Column(String(34), primary_key=True)
    """primary key holds a guid"""

    created     = Column(DateTime(), default=datetime.now())
    """timestamp"""

    softlimit   = Column(DateTime(), default=datetime.now())
    """timestamp, session must show activity before this time to be renewed"""

    hardlimit   = Column(DateTime(), default=datetime.now())
    """timestamp, after this time the session will be removed regardless"""

    userid      = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    """foreign key to User, on cascade delete is on"""

    user        = relationship(User)
    """ORM link to User"""


class PendingUser(Base):
    """
    ORM representation of a PendingUser (a newly registered user awaiting confirmation).
    """

    __tablename__ = 'pendinguser'

    id          = Column(String(34), primary_key=True)  # holds a guid
    """primary key holds a guid"""

    email       = Column(String(100, collation='NOCASE'), unique=True)
    """user name (a valid email address)"""

    name        = Column(String(100))
    """full name"""

    password    = Column(String(100))
    """hashed password"""

    created     = Column(DateTime(), default=datetime.now())
    """timestamp"""

    expires     = Column(DateTime(), default=datetime.now())
    """timestamp, after this time the session will be removed regardless"""


class PasswordReset(Base):
    """
    ORM representation of a PasswordReset event awaiting confirmation.

    This PasswordReset will be deleted if the corresponding user is deleted.
    """

    __tablename__ = 'passwordreset'

    id          = Column(String(34), primary_key=True)  # holds a guid
    """primary key holds a guid"""

    created     = Column(DateTime(), default=datetime.now())
    """timestamp"""

    expires     = Column(DateTime(), default=datetime.now())
    """timestamp, after this time the session will be removed regardless"""

    userid      = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    """foreign key to User, on cascade delete is on"""

    user        = relationship(User)
    """ORM link to User"""


verifysession_params  = ParameterSet({'sessionid': (r"[01-9a-f]{32}", 34)})
logout_params         = ParameterSet({})
login_login_params    = ParameterSet({'login': ('Login', 5), 'password': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
login_register_params = ParameterSet({'login': ('Register', 8), 'name': (r"[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N} ]+", 100), 'password': (allowed_password, 64), 'password2': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
login_forgot_params   = ParameterSet({'login': ('Forgot', 6), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
newpassword_params    = ParameterSet({'choose': ('Choose', 6), 'password': (allowed_password, 64), 'password2': (allowed_password, 64), 'resetid': (r"[01-9a-f]{32}", 34)})
stats_params          = ParameterSet()
confirmation_params   = ParameterSet({'confirmationid': (r"[01-9a-f]{32}", 34)})


def max_body(limit):
    """
    A :func:`falcon.before` hook to limit the size of request body.

    Arguments:
        limit(int): maximum size in bytes of the request body

    Raises:
        :exception:`falcon.HTTPPayloadTooLarge` when the body of the request exceeds `limit`

    Returns:
        a hook function
    """
    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPPayloadTooLarge(
                'Request body is too large', msg)

    return hook


class LoginResource:
    """
    Routing endpoint that serves the action of a login form.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a logon POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as www-formencoded parameters in the request body.

        On success it will set the `Location` header to :attr:`APPLICATION` and return a session cookie.

        On failure it will set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to :attr:`falcon.HTTP_303`.

        Other Parameters:
            email: the username of the user (a valid email address)
            password: the password
            login: the literal text `Login`

        Typically these parameters would correspond to input fields in an
        HTML form and a submit button with a `name=Login` attribute and
        send as input parameters in the body of the request.
        """
        logger.info('LoginResource')
        global DBSession
        if not login_login_params.check(req.params):
            logger.info('unauthorized, params do not have a proper format')
        else:
            email = req.params['email'].lower()
            session = DBSession()
            user = session.query(User).filter(User.email == email).first()
            if user:
                logger.info(f"valid user found {user.email}")
                if checkpassword(req.params['password'], user.password):
                    # self.redirect_header("Login succeeded", APPLICATION)
                    for s in session.query(Session).filter(Session.userid == user.id):
                        session.delete(s)
                    now = datetime.now()
                    softlimit = now + timedelta(minutes=SOFTTIMEOUT)
                    hardlimit = now + timedelta(minutes=HARDTIMEOUT)
                    ns = Session(userid=user.id, id=guid().hex, created=now, softlimit=softlimit, hardlimit=hardlimit)
                    session.add(ns)
                    session.commit()
                    resp.set_cookie('session', ns.id, domain=DOMAIN, path='/', http_only=False)
                    # falcon 3 supports samesite argument in set_cookie but falcon 2 doesn't
                    resp._cookies['session']['samesite'] = 'Lax'
                    logger.success(f'user succesfully authenticated {user.email}')
                    resp.status = falcon.HTTP_303
                    resp.location = APPLICATION
                    return
                else:
                    logger.info(f'user authentication failed for known user {user.email}')
            else:
                logger.info(f'user authentication failed for unknown user {email}')
        resp.status = falcon.HTTP_303
        resp.location = f'{LOGINSCREEN}?failed'


class RegisterResource:
    """
    Routing endpoint that serves the action of a registration form.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a register POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as www-formencoded parameters in the request body.

        On success it will create a pending user request and send an email with a confirmation link.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to :attr:`falcon.HTTP_303`.

        Other Parameters:
            email: the username of the user (a valid email address)
            name: the full name of the user
            password: the password ( 8 >= length <= 64, must contain at lease 1 lowercase, 1 uppercase, 1 digit and 1 special char.
            password2: must be identical to the password parameter
            login: the literal text `Register`

        Typically these parameters would correspond to input fields in an
        HTML form and a submit button with a `name=Register` attribute and
        send as input parameters in the body of the request.
        """
        logger.info('RegisterResource')
        global DBSession
        session = DBSession()
        resp.status = "303 Registration pending confirmation, email sent to email address"
        resp.location = f"{LOGINSCREEN}?pending"
        if not login_register_params.check(req.params):
            logger.info('unauthorized, login register params do not have proper format')
        else:
            params = req.params
            # TODO lowercase email everywhere
            email = params['email'].lower()
            user = session.query(User).filter(User.email == email).first()
            # We always return the same response (and redirect) no matter
            # whether the email is in use or not or if anything else is wrong
            # this is to prevent indexing, i.e. checking which email addresses are in use
            if params['password'] != params['password2']:
                logger.info("passwords are not identical")
            elif user:
                logger.info(f'email already in use {user.email}')
            else:
                user = session.query(PendingUser).filter(PendingUser.email == email).first()
                if user:  # we delete previous pending registration to prevent database overfilling
                    logger.info('previous registration not yet confirmed')
                    session.delete(user)
                    session.commit()
                else:
                    logger.info('first registration')
                pu = PendingUser(id=guid().hex, email=email, password=newpassword(params['password']), name=params['name'])
                session.add(pu)
                session.commit()
                # TODO limit number of emails sent to same address
                user = session.query(PendingUser).filter(PendingUser.email == email).first()
                logger.info(f"sending confirmation mail to {user.email} ({user.name})")
                logger.info(f"confirmation id: {pu.id}")
                u, p, s = fetch_smtp_params()
                logger.info(f"mailer {u}@{s} (password not shown ...)")
                if mail(EMAILTEMPLATE_REGISTER.format(name=user.name, website=WEBSITE, link=f"{CONFIRMREGISTRATION}?confirmationid={pu.id}"), "Confirm your registration", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p):
                    logger.success('mail successfully sent')
                else:
                    logger.error('mail not sent')


class ForgotPasswordResource:
    """
    Routing endpoint that serves the action of a forgot password form.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a forgotpassword POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as www-formencoded parameters in the request body.

        On success it will create a password reset request and send an email with a confirmation link.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to ;attr:`falcon.HTTP_303`.

        Other Parameters:
            email: the username of the user (a valid email address)
            login: the literal text `Forgot`

        Typically these parameters would correspond to input fields in an
        HTML form and a submit button with a `name=Forgot` attribute and
        send as input parameters in the body of the request.
        """
        logger.info('ForgotPasswordResource')
        global DBSession
        session = DBSession()
        # we always send the same response, no matter if the user exists or not
        resp.status = falcon.HTTP_303
        resp.location = f"{LOGINSCREEN}?checkemail"

        params = req.params
        if not login_forgot_params.check(params):
            logger.info('unauthorized, login forgot params do not have proper format')
        else:
            email = params['email'].lower()
            user = session.query(User).filter(User.email == email).first()

            user = session.query(User).filter(User.email == email).first()
            if not user:  # no user found but we are not providing this information
                logger.info(f"no user found {email}")
            else:
                logger.info(f"password reset request received for existing user {email}")
                pr = PasswordReset(id=guid().hex, userid=user.id)
                session.add(pr)
                session.commit()
                logger.info(f"sending confirmation mail to {user.email} ({user.name})")
                logger.info(f"reset confirmation id: {pr.id}")
                u, p, s = fetch_smtp_params()
                if mail(EMAILTEMPLATE_FORGOTPASSWORD.format(name=user.name, website=WEBSITE, link=f"{RESETPASSWORD}?confirmationid={pr.id}"), "Password change request", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p):
                    logger.success('mail successfully sent')
                else:
                    logger.error('mail not sent')


class VerifySessionResource:
    """
    Routing endpoint that serves as the internal endpoint to verify the existence of a valid session.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a verifysession POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            On success the response body will contain the following key=value pairs separated by newline characters:

                - email(str)
                - id(int)
                - name(str)
                - superuser(bool)

        The method expects its input as www-formencoded parameters in the request body.

        On success it will the session data and set the response status to :attr:`falcon.HTTP_200`.

        On failure it will do nothing and return a response status of :attr:`falcon.HTTP_404`.

        Other Parameters:
            email: the username of the user (a valid email address)
            login: the literal text `Forgot`

        This method should not be called from the browser. It is typically called by other backend servers to verify
        the validity of a session and get the email address, name and superuser status of that session.

        It does not accept requests that have an `X-Forwarded-Host` header defined, so if the authserver and the backend
        server are positioned behind a reverse proxy that adds these headers (like traefik) all things will be fine.
        """

        logger.info('VerifySessionResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        # we only allow sessions to be verified by apps running on the same
        # network, i.e. they should not have any X- headers present
        if (h := req.get_header('X-Forwarded-Host')) is not None:
            logger.info(f'unauthorized, verifysession called from outside {h}')
        # verify that incoming parameters are what we expect
        elif not verifysession_params.check(req.params):
            logger.info('unauthorized, sessionid does not have proper format')
        # if the session is known, compose the response with user data
        elif (info := self.session_active(session, req.params['sessionid'])) is not None:
            resp.body = info
            resp.status = falcon.HTTP_200
        else:
            logger.info(f"unauthorized, no valid session found: {req.params['sessionid']}")
        # clean up stale sessions
        session.commit()
        for s in session.query(Session).filter(Session.hardlimit <= datetime.now()):
            logger.info(f'deleting session {s.id} for {s.user.email}')
            session.delete(s)

    def session_active(self, session, sessionid):
        """
        Check whether a sessionid represents an active session.

        A session is active

            - if the sessionid exists

            - its :attr:`Session.softlimit` is in the future.

        If a session is found to be valid, its :attr:`Session.softlimit` is set to :attr:`SOFTTIMEOUT` minutes from now.

        Arguments:
            session(DBSession): SQLAlchemy session
            sessionid(str): a sessionid

        Returns:
            On success: a bytes object with a newline separated list of key=value pairs

            On failure: None
        """
        now = datetime.now()
        for s in session.query(Session).filter(Session.id == sessionid, now < Session.hardlimit):
            if now < s.softlimit:
                logger.success(f'active session found: {sessionid} {s.user.email}')
                logger.info(f'email={s.user.email} id={s.user.id} name={s.user.name} superuser={s.user.superuser}')
                s.softlimit = now + timedelta(minutes=SOFTTIMEOUT)
                logger.debug(s.softlimit)
                return bytes(f'email={s.user.email}\nid={s.user.id}\nname={s.user.name}\nsuperuser={s.user.superuser}', 'utf-8')
        return None


class LogoutResource:
    """
    Routing endpoint that serves the action of a logout form.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a logout POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects no input parameters in the request body.
        A valid sessionid cookie should be present.

        On success it will remove the session.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to ;attr:`falcon.HTTP_303`.
        """
        logger.info('LogoutResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN
        if not logout_params.check(req.params):
            logger.info('bad request: logout request should not have parameters')
        elif cv := req.get_cookie_values('session'):
            cookie = cv[0]
            logger.info(cookie)
            for s in session.query(Session).filter(Session.id == cookie):
                logger.debug(f"deleting session {s.id} for user {s.user.email}")
                logger.success(f'logout authorized for user {s.user.email}')
                session.delete(s)
                session.commit()
                resp.status = falcon.HTTP_303
            return
        logger.info('logout unauthorized, session not found or no session cookie present')


class ChoosePasswordResource:
    """
    Routing endpoint that serves the action of a choose new password form.
    """
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        """
        Handle a choose password POST request.

        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as www-formencoded parameters in the request body.
        It also

        On success it will change the password of the user.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to :attr:`falcon.HTTP_303`.

        Other Parameters:
            resetid: an id that should be present in the :class:`PendingUser` table
            password: the password ( 8 >= length <= 64, must contain at lease 1 lowercase, 1 uppercase, 1 digit and 1 special char.
            password2: must be identical to the password parameter
            choose: the literal text `Choose`

        Typically these parameters would correspond to input fields in an
        HTML form and a submit button with a `choose=Choose` attribute and
        send as input parameters in the body of the request.
        """
        logger.info('ChoosePasswordResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN
        if not newpassword_params.check(req.params):
            logger.info('bad request: malformed parameters')
        else:
            params = req.params
            if params['password'] != params['password2']:
                logger.info("passwords are not identical")
            else:
                for resetuser in session.query(PasswordReset).filter(PasswordReset.id == params['resetid']):
                    logger.success(f'password reset for user {resetuser.user.email}')
                    user = resetuser.user
                    user.password = newpassword(params['password'])
                    resp.status = falcon.HTTP_303
                    resp.location = f"{LOGINSCREEN}?resetsuccessful"
                    session.delete(resetuser)
                    session.commit()
                    return
                logger.info('resetid not found or expired')


class StatsResource:
    """
    Routing endpoint that serves as the REST endpoint for user information overviews.

    It can return information in JSON format on :class:`User`, :class:`PendingUser`,
    :class:`PasswordReset` and :class:`Session`.

    Access is restricted to logged in users woth the superuser role.
    """
    @falcon.before(max_body(0))
    def on_post(self, req, resp, item):
        """
        Handle a stats/{item} POST request, typically one initialed by an AJAX call.

        Arguments:
            req: the request
            resp: the response
            item(str): the kind of item for which a list should be returned

        Returns:
            None

        Even though this is a POST handler, it should have no input parameters in the body.
        The items that can be requested are:

            - `users`: to return a JSON encoded list of :class:`User` objects

            - `sessions`: to return a JSON encoded list of :class:`Session` objects

            - `pendingusers`: to return a JSON encoded list of :class:`PendingUser` objects

            - `passwordreset`: to return a JSON encoded list of :class:`PasswordReset` objects

        On success the response body will contain a bytes object that is JSON data (in UTF-8 encoding).
        Note that any password attributes will be stripped form the output.

        Example:

            JSON data is returned an object with a data attribute::

                {
                    "data": [
                                {"id": 165675, "email": "abc@example.org", ...},
                                {"id": 365625, "email": "def@example.org", ...},
                                ...
                            ]
                }

        """
        logger.info('StatsResource')
        itemmap = {'users': User, 'sessions': Session, 'pendingusers': PendingUser, 'passwordresets': PasswordReset}
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN
        params = req.params
        if not stats_params.check(params) or item not in itemmap:
            logger.info('unauthorized, stats params do not have proper format')
        elif cv := req.get_cookie_values('session'):
            cookie = cv[0]
            logger.info(cookie)
            for s in session.query(Session).filter(Session.id == cookie):
                if s.user.superuser:
                    logger.success(f'/stats/{item} authorized for user {s.user.email}')
                    resp.status = falcon.HTTP_200
                    ob = itemmap[item]
                    users = json.dumps([u for u in session.query(ob)], default=alchemyencoder)
                    logger.debug(users)
                    resp.body = bytes(f'{{"data": {users}}}', 'utf-8')
                    return
                logger.info(f'unauthorized, {s.user.email} (s.user.name) is not a superuser ({s.user.superuser})')
                return
            logger.info(f"unauthorized, no valid session found: {self.cookie['session'].value}")
        else:
            logger.info('unauthorized, no session cookie provided')


class ConfirmRegistrationResource:
    """
    Routing endpoint that serves the registration confirmation link.
    """
    @falcon.before(max_body(0))
    def on_get(self, req, resp):
        """
        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as query parameters in the url.

        On success it will create a :class:`User` from the corresponding :class:`PendingUser`.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`.

        It will always set the response status to :attr:`falcon.HTTP_303`.

        Other Parameters:
            confirmationid: an id that should be present in the :class:`PendingUser` table
        """
        logger.info('ConfirmRegistrationResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN
        if not confirmation_params.check(req.params):
            logger.info('confirmregistration parameters not ok')
        else:
            # TODO check for expiration and remove expired entries
            resp.status = falcon.HTTP_303
            confirmationid = req.params['confirmationid']
            user = session.query(PendingUser).filter(PendingUser.id == confirmationid).first()
            if user:
                logger.success(f'confirmregistration succeeded for {user.email} ({user.name})')
                # copy user to User table
                ns = User(email=user.email, password=user.password, name=user.name)
                session.add(ns)
                session.commit()
                # redirect to login page
                resp.location = f"{LOGINSCREEN}?confirmed"
            else:  # no pending confirmation or expired, redirect to login page
                logger.info(f'confirmregistration link expired or not present {confirmationid}')
                resp.location = f"{LOGINSCREEN}?expired"


class ConfirmForgotPasswordResource:
    """
    Routing endpoint that serves the password reset confirmation link.
    """
    @falcon.before(max_body(0))
    def on_get(self, req, resp):
        """
        Arguments:
            req: the request
            resp: the response

        Returns:
            None

        The method expects its input as query parameters in the url.

        On success it will create a :class:`User` from the corresponding :class:`PendingUser`.

        On failure it will do nothing.

        It will always set the `Location` header to :attr:`LOGINSCREEN`. If a pending request was found,
        `?choosepassword=id` will be appended to the url. If not `?expired` will be added.

        It will always set the response status to :attr:`falcon.HTTP_303`.

        Other Parameters:
            confirmationid: an id that should be present in the :class:`PasswordReset` table
        """
        logger.info('ConfirmForgotPasswordResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN
        if not confirmation_params.check(req.params):
            logger.info('resetpassword parameters not ok')
        else:
            resp.status = falcon.HTTP_303
            confirmationid = req.params['confirmationid']
            # TODO remove PasswordReset after successful confirm
            if pr := session.query(PasswordReset).filter(PasswordReset.id == confirmationid).first():
                logger.success('resetpassword confirmation successful')
                resp.location = f"{LOGINSCREEN}?choosepassword={pr.id}"
            else:  # no pending confirmation or expired, redirect to login page
                logger.info('resetpassword link not present or expired')
                resp.location = f"{LOGINSCREEN}?expired"


def fetch_admin_params():
    """
    Get admin variables from file or environment.

    Enviroment variables overrule variables in files.

    Returns:
        tuple(admin_user, admin_password)

    Module level attributes referenced:

    - :attr:`ADMIN_USER_FILE` filename of file containing super user username (valid email address)
    - :attr:`ADMIN_USER` username (valid email address) of super user, will override ADMIN_USER_FILE
    - :attr:`ADMIN_PASSWORD_FILE` filename of file containing super user password in plaintext
    - :attr:`ADMIN_PASSWORD` super user password in plaintext, will override ADMIN_PASSWORD_FILE

    """
    env = {}
    for var in ('ADMIN_USER', 'ADMIN_PASSWORD'):
        if var in os.environ and os.environ[var].strip() != '':
            env[var] = os.environ[var]
        else:
            varf = var + '_FILE'
            if varf in os.environ:
                with open(os.environ[varf]) as f:
                    env[var] = f.read().strip()
            else:
                raise KeyError(f'{var} and {varf} not defined in environment')

    return env['ADMIN_USER'], env['ADMIN_PASSWORD']


def add_superuser():
    """
    Add superuser account to :class:`User` table.

    Will remove any user account with the same name along with any associated session.
    """
    global DBSession
    username, password = fetch_admin_params()
    session = DBSession()
    for s in session.query(User).filter(User.email == username):
        logger.info(f"deleting user {s.email}")
        session.delete(s)
    session.commit()
    ns = User(email=username, password=newpassword(password), name='Administrator', superuser=True)
    session.add(ns)
    logger.info(f"adding admin user {ns.email}")
    session.commit()
    for s in session.query(Session):
        logger.info(f"{s.id} {s.created} {s.userid}")
    session.close()
    return True


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """
    Enable cascading constraint on the SQLAlchemy tables.

    See: https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#foreign-key-support
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_sessionmaker(connection, timeout, retries):
    """
    Create and initialize a global :class:`sqlalchemy.orm.sessionmaker`.

    Arguments:
        connection(str): a sqlite connection string
        timeout(int): number of seconds to wait between connection retries. doubles with evert attempt.
        retries(int): number of times to retry a connection to the database.

    Returns:
        bool

    The :class:`sqlalchemy.orm.sessionmaker` object is stored in the global :attr:`DBSession`.
    """
    global DBSession
    # this does not open a connection (yet), that will happen on create_all
    db_engine = create_engine(connection, pool_pre_ping=True)

    # we try to connect to the database several times
    waited = 0
    for i in range(1, retries):
        try:
            Base.metadata.create_all(db_engine)
            break
        except Exception as e:
            logger.exception(e)
            logger.info(f"Database connection refused trial {i}/{retries}, now waiting {timeout} seconds ...")
            sleep(timeout)
            waited += timeout
            timeout *= 2
            continue
    else:
        logger.critical(f"No database connections after {retries} tries ({waited} seconds)")
        return False
    DBSession = sessionmaker(bind=db_engine)
    return True
