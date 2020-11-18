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
import usercustomize

from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.parse import urlparse, unquote_plus
from datetime import datetime, date, timedelta
from uuid import uuid4 as guid
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from os import urandom
import os
from smtp import fetch_smtp_params, mail
from decimal import Decimal
import json
from collections import defaultdict
from time import sleep

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, sessionmaker

from loguru import logger

from regex import compile  # we use an alternative regular expression library here to support unicode classes like \p{L}
from regex.regex import Pattern


def number(variable, default):
    """
    Return the integer in the environment variable.
    """
    if variable in os.environ:
        return int(os.environ[variable])
    return int(default)


# domain to be used in session cookie
DOMAIN              = os.environ['DOMAIN']               # e.g. yourdomain.org
# redirect locations for successful logon
APPLICATION         = os.environ['APPLICATION']          # e.g. /books
LOGINSCREEN         = os.environ['LOGINSCREEN']          # e.g. /books/login.html
# these get used in confirmation emails:
CONFIRMREGISTRATION = os.environ['CONFIRMREGISTRATION']  # e.g. https://server.yourdomain.org/auth/confirmregistration
RESETPASSWORD       = os.environ['RESETPASSWORD']        # e.g. https://server.yourdomain.org/auth/resetpassword

# session limits in minutes
SOFTTIMEOUT = number('SOFTTIMEOUT', 30)
HARDTIMEOUT = number('HARDTIMEOUT', 8 * 60)

# confirmation limits in minutes
PWRESETTIMEOUT = number('PWRESETTIMEOUT', 1 * 60)
REGISTERTIMEOUT = number('REGISTERTIMEOUT', 1 * 60)

SESSIONID_pattern   = compile(r"[01-9a-f]{32}")
PASSWORD_lower      = compile(r"[a-z]")
PASSWORD_upper      = compile(r"[A-Z]")
PASSWORD_digit      = compile(r"[01-9]")
PASSWORD_special    = compile(r"[ !|@#$%^&*()\-_.,<>?/\\{}\[\]]")


def newpassword(password):
    salt = urandom(16)
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + dk.hex()


def checkpassword(password, reference):
    salt = bytes.fromhex(reference[:32])
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return compare_digest(salt.hex() + dk.hex(), reference)


def allowed_sessionid(s):
    """
    Check is s is a sessionid in a proper format (32 lowercase hex digits).
    """
    if len(s) > 32:  # protect against overly long strings
        return False
    return bool(SESSIONID_pattern.fullmatch(s))


def verify_login_params(params):

    if 'login' not in params:
        return False
    if params['login'] not in ('Login', 'Register', 'Forgot'):
        return False
    pset = set(params.keys())
    if params['login'] == 'Login':
        if pset != {'login', 'password', 'email'}:
            return False
    elif params['login'] == 'Register':
        if pset != {'login', 'password', 'password2', 'email', 'name'}:
            return False
    elif params['login'] == 'Forgot':
        if pset != {'login', 'email'}:
            return False
    else:
        return False
    return True


def verify_verifysession_params(params):
    if len(params) != 1 or 'sessionid' not in params:
        return False
    if allowed_sessionid(params['sessionid']):
        return True
    return False


def verify_stats_params(params):
    logger.error('verify_stats_params does not have a proper implementation yet')
    return True


def allowed_password(s):
    """
    Check if a password meets the complexity criteria:

    - between 8 and 64 characters,
    - contain at least 1 lowercase, 1 uppercase, 1 digit and 1 special character
    - it may not contain characters outside those classes
    - character classes *are* unicode aware
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


def get_params(body):
    """
    Get the form encoded parameters from the body of a POST request.

    The conten type should be application/x-www-form-urlencoded; charset=UTF-8.

    returns a dict name:str -> value:str
    """
    params = defaultdict(str)
    for p in body.decode('utf-8').split('&'):
        if len(p.strip()) == 0:
            continue
        kv = p.split('=', maxsplit=1)
        if kv:
            k = unquote_plus(kv[0]).strip()
            v = ''
            if len(kv) > 1:
                v = unquote_plus(kv[1])
            params[k] = v
            logger.debug(f'param {k}={v}')
    return params


def valid_session(cookie, session):
    if 'session' not in cookie:
        return False
    if not allowed_sessionid(cookie['session'].value):
        return False
    return bool(session.query(Session).filter(Session.id == cookie['session'].value).one())


class ParameterSet:

    """
    Defines allowable input parameters for a POST request.
    """

    def __init__(self, specs):
        """
        specs is a dict name --> (ex, maxlength)

        name is a case sentive name of an allowed input parameter
        ex is either a string, a regular expression or a callable
        maxlength is an integer

        if ex is a string it is converted to a regular expression.
        if ex is a callable it should return a boolean indicating the validity of a value.
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
        return true if the params are all allowed.

        params is a dict name --> value where name and value are strings

        if params contains extra parameters or it is missing items it is considered invalid.
        """
        if set(params.keys()) == self.keys:  # all input names should be present
            for k, v in params.items():
                r, length = self.specs[k]
                if len(v) > length:  # values that are too long are invalid
                    return False
                elif isinstance(r, Pattern):
                    if not bool(r.fullmatch(v)):
                        return False
                elif not r(v):
                    return False
        return True


Base = declarative_base()


def alchemyencoder(obj):
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
    __tablename__ = 'user'
    id          = Column(Integer, primary_key=True)
    email       = Column(String(100), unique=True)
    password    = Column(String(100))
    name        = Column(String(100))
    superuser   = Column(Boolean(), default=False)
    created     = Column(DateTime(), default=datetime.now())
    active      = Column(Boolean(), default=True)
    attempts    = Column(Integer, default=0)
    accessed    = Column(DateTime(), default=datetime.now())
    locked      = Column(DateTime(), default=datetime.now())


class Session(Base):
    __tablename__ = 'session'
    id          = Column(String(34), primary_key=True)  # holds a guid
    created     = Column(DateTime(), default=datetime.now())
    softlimit   = Column(DateTime(), default=datetime.now())
    hardlimit   = Column(DateTime(), default=datetime.now())
    userid      = Column(Integer, ForeignKey('user.id'))
    user        = relationship(User)


class PendingUser(Base):
    __tablename__ = 'pendinguser'
    id          = Column(String(34), primary_key=True)  # holds a guid
    email       = Column(String(100), unique=True)
    name        = Column(String(100))
    password    = Column(String(100))
    created     = Column(DateTime(), default=datetime.now())
    expires     = Column(DateTime(), default=datetime.now())


class PasswordReset(Base):
    __tablename__ = 'passwordreset'
    id          = Column(String(34), primary_key=True)  # holds a guid
    created     = Column(DateTime(), default=datetime.now())
    expires     = Column(DateTime(), default=datetime.now())
    userid      = Column(Integer, ForeignKey('user.id'))
    user        = relationship(User)


# we catch exceptions in this method ourselves
# because otherwise they are caught by the server, w.o. a message,
# and nothing is returned. That causes a 502 Bad gateway in Traefik
class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    verifysession_params = ParameterSet({'sessionid': (r"[01-9a-f]{32}", 34)})
    logout_params = ParameterSet({})
    login_login_params = ParameterSet({'login': ('Login', 5), 'password': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
    login_register_params = ParameterSet({'login': ('Register', 8), 'name': (r"[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N} ]+", 100), 'password': (allowed_password, 64), 'password2': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})

    def log_message(self, format, *args):
        """
        Overridden method, now logs original messages on trace level.
        """
        logger.trace(f"{self.address_string()} {format % args}")

    def redirect_header(self, msg, location):
        """
        Set location header.

        msg is the message added to the HTTP response code
        location the URL to redirect to

        Note that the headers are not ended and the session cookie is
        not cleared.
        """
        self.send_response(HTTPStatus.SEE_OTHER, msg)
        self.send_header("Location", location)

    def redirect(self, msg, location):
        """
        Set location header and clear session cookie.

        msg is the message added to the HTTP response code
        location the URL to redirect to.
        """
        self.send_response(HTTPStatus.SEE_OTHER, msg)
        self.send_header("Location", location)
        self.send_session_cookie(None)
        self.end_headers()

    def login_failed(self):
        self.redirect("Login failed", f"{LOGINSCREEN}?failed")

    def get_cookies(self):
        c = self.headers.get('Cookie')
        cookie = SimpleCookie()
        if c:
            cookie.load(c)
        return cookie

    def send_session_cookie(self, session_id):
        cookie = SimpleCookie()
        cookie['session'] = session_id
        cookie['session']['samesite'] = 'Lax'
        cookie['session']['domain'] = DOMAIN
        cookie['session']['path'] = '/'
        for morsel in cookie.values():
            self.send_header("Set-Cookie", morsel.OutputString())

    def do_login_login(self):
        logger.info('/login login=Login')
        if not MyHTTPRequestHandler.login_login_params.check(self.params):
            logger.info('unauthorized, sessionid does not have proper format')
        else:
            email = self.params['email']
            user = self.session.query(User).filter(User.email == email).first()
            if user:
                logger.info(f"valid user found {user.email}")
                if checkpassword(self.params['password'], user.password):
                    self.redirect_header("Login succeeded", APPLICATION)
                    for s in self.session.query(Session).filter(Session.userid == user.id):
                        self.session.delete(s)
                    now = datetime.now()
                    softlimit = now + timedelta(minutes=SOFTTIMEOUT)
                    hardlimit = now + timedelta(minutes=HARDTIMEOUT)
                    ns = Session(userid=user.id, id=guid().hex, created=now, softlimit=softlimit, hardlimit=hardlimit)
                    self.session.add(ns)
                    self.send_session_cookie(ns.id)
                    logger.success(f'user succesfully authenticated {user.email}')
                    return
                else:
                    logger.info(f'user authentication failed for known user {user.email}')
            else:
                logger.info(f'user authentication failed for unknown user {email}')
        self.login_failed()

    def do_login_register(self):
        logger.info('/login login=Register')
        if not MyHTTPRequestHandler.login_register_params.check(self.params):
            logger.info('unauthorized, login register params do not have proper format')
        else:
            email = self.params['email']
            user = self.session.query(User).filter(User.email == email).first()
            # We always return the same response (and redirect) no matter
            # whether the email is in use or not or if anything else is wrong
            # this is to prevent indexing, i.e. checking which email addresses are in use
            params = self.params
            if params['password'] != params['password2']:
                logger.info("passwords are not identical")
            elif user:
                logger.info(f'email already in use {user.email}')
            else:
                user = self.session.query(PendingUser).filter(PendingUser.email == params['email']).first()
                if user:  # we delete previous pending registration to prevent database overfilling
                    logger.info('previous registration not yet confirmed')
                    self.session.delete(user)
                    self.session.commit()
                else:
                    logger.info('first registration')
                pu = PendingUser(id=guid().hex, email=params['email'], password=newpassword(params['password']), name=params['name'])
                self.session.add(pu)
                self.session.commit()
                # TODO we should make sure that a limited number of emails are sent to the same address
                user = self.session.query(PendingUser).filter(PendingUser.email == params['email']).first()
                logger.success(f"sending confirmation mail to {user.email} (user.name)")
                u, p, s = fetch_smtp_params()
                mail(f"""
                Hi {user.name},

                Please confirm your registration on Book collection.

                {CONFIRMREGISTRATION}?{pu.id}

                """,
                     "Confirm your Book collection registration", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p)
            self.redirect_start("Registration pending confirmation, email sent to email address", f"{LOGINSCREEN}?pending")
            self.send_session_cookie(None)

    def do_login_forgot(self):
        logger.info('/login login=Forgot')
        email = self.params['email']
        user = self.session.query(User).filter(User.email == email).first()
        params = self.params

        # we always send the same response, no matter if the user exists or not
        self.redirect_start("Email sent", f"{LOGINSCREEN}?checkemail")
        self.send_session_cookie(None)

        user = self.session.query(User).filter(User.email == params['email']).first()
        if not user:  # no user found but we are not providing this information
            logger.info(f"no user found {params['email']}")
        else:
            logger.info(f"password reset request received for existing user {params['email']}")
            pr = PasswordReset(id=guid().hex, userid=user.id)
            self.session.add(pr)
            self.session.commit()
            u, p, s = fetch_smtp_params()
            mail(f"""
            Hi {user.name},

            We received a request to reset your password. If it wasn't you, please ignore this message.
            Otherwise, follow this link and select a new password.

            RESETPASSWORD?{pr.id}

            """, "Password change request", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p)
        return None

    def do_login(self):
        if 'login' in self.params and self.params['login'] == 'Login':
            self.do_login_login()
        elif self.params['login'] == 'Register':
            self.do_login_register()
        elif self.params['login'] == 'Forgot':
            self.do_login_forgot()
        else:
            logger.info('no login parameter')
            self.login_failed()

    def session_active(self, sessionid):
        now = datetime.now()
        for s in self.session.query(Session).filter(Session.id == sessionid, now < Session.hardlimit):
            if now < s.softlimit:
                logger.success(f'active session found: {sessionid} {s.user.email}')
                logger.info(f'email={s.user.email} id={s.user.id} name={s.user.name} superuser={s.user.superuser}')
                s.softlimit = now + timedelta(minutes=SOFTTIMEOUT)
                logger.debug(s.softlimit)
                return bytes(f'email={s.user.email}\nid={s.user.id}\nname={s.user.name}\nsuperuser={s.user.superuser}', 'utf-8')
        return None

    def do_verifysession(self):
        params = self.params
        # we only allow sessions to be verified by apps running on the same
        # network, i.e. they should not have any X- headers present
        if self.xheaders_present:
            logger.info('unauthorized, verifysession called from outside')
        # verify that incoming parameters are what we expect
        elif not MyHTTPRequestHandler.verifysession_params.check(self.params):
            logger.info('unauthorized, sessionid does not have proper format')
        # if the session is known, compose the response with user data
        elif (info := self.session_active(self.params['sessionid'])) is not None:
            self.send_response(HTTPStatus.OK, "valid session")
            return info
        else:
            logger.info(f"unauthorized, no valid session found: {params['sessionid']}")
        self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
        self.session.commit()
        for s in self.session.query(Session).filter(Session.hardlimit <= datetime.now()):
            self.session.delete(s)
            logger.info(f'deleted session {s.id} for {s.user.email}')
        return None

    def do_logout(self):
        if not MyHTTPRequestHandler.logout_params.check(self.params):
            logger.info('bad request: logout request should not have parameters')
        elif 'session' in self.cookie:
            logger.info(self.cookie['session'])
            for s in self.session.query(Session).filter(Session.id == self.cookie['session'].value):
                logger.debug(f"deleting session {s.id} for user {s.user.email}")
                self.session.delete(s)
                self.send_response(HTTPStatus.OK)
                self.send_header("Location", LOGINSCREEN)
                logger.success(f'logout authorized for user {s.user.email}')
                return bytes(s.user.email, 'utf-8')
        self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
        logger.info('logout unauthorized, session not found or no session cookie present')
        return None

    def do_newpassword(self):
        params = self.params
        if not allowed_password(params['password']):
            logger.info(f"invalid password format [{params['password'][:70]}]")
        elif not allowed_password(params['password2']):
            logger.info(f"invalid password format [{params['password2'][:70]}]")
        elif params['password'] != params['password2']:
            logger.info("passwords are not identical")
            # TODO check for expiration and remove expired sessions (and successful session )
        elif resetuser := self.session.query(PasswordReset).filter(PasswordReset.id == params['resetid']).first():  # resetid is a hidden field
            logger.success(f'password reset for user {resetuser.user.email}')
            user = resetuser.user
            user.password = newpassword(params['password'])
            self.redirect_start("Password reset successful", f"{LOGINSCREEN}?resetsuccessful")
            self.send_session_cookie(None)
        else:
            logger.info('resetid not found or expired')
            self.redirect_start("Password reset failed", f"{LOGINSCREEN}?resetfailed")
            self.send_session_cookie(None)
        return None

    def do_unknown(self):
        logger.info('url not found')
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")
        return None

    def do_stats(self):
        params = self.params
        url = urlparse(self.path)
        # TODO we may want to whitelist this for only localhost in traefik
        # verify that incoming parameters are what we expect
        if not verify_stats_params(params):
            self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
            logger.info('unauthorized, sessionid does not have proper format')
        if url.query not in ('users', 'sessions', 'pendingusers', 'passwordresets'):
            self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
            logger.info('unauthorized, url.query does not have proper format')
        # if the session is known, compose the response with user data
        # TODO add a hard timelimit to the session
        if 'session' in self.cookie:
            logger.info(self.cookie['session'])
            for s in self.session.query(Session).filter(Session.id == self.cookie['session'].value):
                if s.user.superuser:
                    logger.success(f'/stats authorized for user {s.user.email}')
                    self.send_response(HTTPStatus.OK, "valid session")
                    ob = {'users': User, 'sessions': Session, 'pendingusers': PendingUser, 'passwordresets': PasswordReset}[url.query]
                    users = json.dumps([u for u in self.session.query(ob)], default=alchemyencoder)
                    return bytes(f'{{"data": {users}}}', 'utf-8')
                logger.info(f'unauthorized, {s.user.email} (s.user.name) is not a superuser ({s.user.superuser})')
                break
            logger.info(f"unauthorized, no valid session found: {self.cookie['session'].value}")
        else:
            logger.info('unauthorized, no session cookie provided')
        self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
        return None

    def dispatch(self, path):
        dispatch_table = {
            '/login':         self.do_login,
            '/verifysession': self.do_verifysession,
            '/logout':        self.do_logout,
            '/newpassword':   self.do_newpassword,
            '/stats':         self.do_stats
        }
        url = urlparse(path)
        if url.path in dispatch_table:
            return dispatch_table[url.path]()
        return self.do_unknown()

    def do_POST(self):
        global DBSession
        # check if an X-header is present
        # this signifies that the request was forwarded by traefik
        # i.e. is coming from the outside

        fromip = self.headers['X-Forwarded-For'] if 'X-Forwarded-For' in self.headers else 'internal net'
        logger.info(self.address_string())
        logger.info(f'POST from {fromip}')
        logger.info(f'url {self.path}')

        self.xheaders_present = False
        for h in self.headers:
            logger.debug(f'{h}: {self.headers[h]}')
            if h.startswith('X-'):
                self.xheaders_present = True
        # try:
        if True:
            # TODO can session act as a context manager (and roll back if an exception happens)?
            self.session = DBSession()
            self.cookie = self.get_cookies()

            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            if content_length > 1000:
                logger.info(f'bad request: body too large {content_length}')
                self.send_error(HTTPStatus.BAD_REQUEST, "Bad request")
                return None

            self.params = get_params(body)

            content = self.dispatch(self.path)

            self.session.commit()
            self.session.close()

            if content:
                logger.debug(f'response content {content}')
                self.send_header("Content-type", "text/html; charset=UTF-8")
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
                self.wfile.flush()
            else:
                self.end_headers()

            logger.debug('done')
            return None
        # except Exception as e:
        #    logger.exception(e)
        #    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        #    return None

    def do_GET(self):
        global DBSession
        try:
            fromip = self.headers['X-Forwarded-For'] if 'X-Forwarded-For' in self.headers else 'internal net'
            logger.info(self.address_string())
            logger.info(f'GET from {fromip}')
            logger.info(f'url {self.path}')

            session = DBSession()
            logger.info(session)
            url = urlparse(self.path)
            if url.path == '/confirmregistration':
                if not allowed_sessionid(url.query):
                    logger.info(f'confirmregistration link not ok {url.query[:40]}')
                    self.redirect("Confirmation link not ok", f"{LOGINSCREEN}?expired")
                else:
                    # TODO check for expiration and remove expired entries
                    user = session.query(PendingUser).filter(PendingUser.id == url.query).first()
                    if user:
                        logger.success(f'confirmregistration succeeded for {user.email} ({user.name})')
                        # copy user to User table
                        ns = User(email=user.email, password=user.password, name=user.name)
                        session.add(ns)
                        session.commit()
                        # redirect to login page
                        self.redirect("Confirmation ok", f"{LOGINSCREEN}?confirmed")
                    else:  # no pending confirmation or expired, redirect to login page
                        logger.info(f'confirmregistration link expired or not present {url.query[:40]}')
                        self.redirect("Confirmation link not ok", f"{LOGINSCREEN}?expired")
                # TODO clean pending users with same email? (note: only expired)
            if url.path == '/resetpassword':
                if not allowed_sessionid(url.query):
                    logger.info(f'resetpassword link not ok {url.query[:40]}')
                    self.redirect("Confirmation link not ok", f"{LOGINSCREEN}?expired")
                elif pr := session.query(PasswordReset).filter(PasswordReset.id == url.query).first():
                    logger.success('resetpassword confirmation successful')
                    self.redirect("Reset request ok", f"{LOGINSCREEN}?choosepassword={pr.id}")
                else:  # no pending confirmation or expired, redirect to login page
                    logger.info('resetpassword link not present or expired')
                    self.redirect("Confirmation link not ok", f"{LOGINSCREEN}?expired")
                # TODO clean pending users with same email? (note: only expired)
            else:
                logger.info('url not found')
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                self.end_headers()

            logger.debug('done')
            return None
        except Exception as e:
            logger.exception(e)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return None


def fetch_admin_params():
    """
    Get admin variables from file or environment.

    enviroment variables overrule variables in files.
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
    session.close()
    return True


def get_sessionmaker(connection, timeout, retries):
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
