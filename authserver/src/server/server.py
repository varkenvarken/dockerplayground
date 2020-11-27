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
    """
    if variable in os.environ:
        return int(os.environ[variable])
    return int(default)


def getvar(variable, default='<unknown>'):
    if variable in os.environ:
        return os.environ[variable]
    return default


# domain to be used in session cookie
DOMAIN              = getvar('DOMAIN')               # e.g. yourdomain.org
# redirect locations for successful logon
APPLICATION         = getvar('APPLICATION')          # e.g. /books
LOGINSCREEN         = getvar('LOGINSCREEN')          # e.g. /books/login.html
# these get used in confirmation emails:
CONFIRMREGISTRATION = getvar('CONFIRMREGISTRATION')  # e.g. https://server.yourdomain.org/auth/confirmregistration
RESETPASSWORD       = getvar('RESETPASSWORD')        # e.g. https://server.yourdomain.org/auth/resetpassword

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
    """
    Return a cryptographic hash of password as a string of hex digits.

    The password is salted with 16 random bytes.
    The salt is prepended as 32 hex digits to the returned hash.
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


class ParameterSet:

    """
    Defines allowable input parameters for a POST request.
    """

    def __init__(self, specs={}):
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
    A json encoder for ORM objects, date and Decimal objects.

    like all default encoders for json it returns strings which are then encoded to json.
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
    userid      = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
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
    userid      = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    user        = relationship(User)


verifysession_params  = ParameterSet({'sessionid': (r"[01-9a-f]{32}", 34)})
logout_params         = ParameterSet({})
login_login_params    = ParameterSet({'login': ('Login', 5), 'password': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
login_register_params = ParameterSet({'login': ('Register', 8), 'name': (r"[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N} ]+", 100), 'password': (allowed_password, 64), 'password2': (allowed_password, 64), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
login_forgot_params   = ParameterSet({'login': ('Forgot', 6), 'email': (r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*", 100)})
newpassword_params    = ParameterSet({'choose': ('Choose', 6), 'password': (allowed_password, 64), 'password2': (allowed_password, 64), 'resetid': (r"[01-9a-f]{32}", 34)})
stats_params          = ParameterSet()
confirmation_params   = ParameterSet({'confirmationid': (r"[01-9a-f]{32}", 34)})


def max_body(limit):

    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPPayloadTooLarge(
                'Request body is too large', msg)

    return hook


class LoginResource:
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        logger.info('LoginResource')
        global DBSession
        if not login_login_params.check(req.params):
            logger.info('unauthorized, params do not have a proper format')
        else:
            email = req.params['email']
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


# TODO make mail work based on templates
class RegisterResource:
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
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
            email = params['email']
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
                if mail(f"""
                Hi {user.name},

                Please confirm your registration on Book Collection.

                {CONFIRMREGISTRATION}?confirmationid={pu.id}

                """, "Confirm your Book Collection registration", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p):
                    logger.success('mail successfully sent')
                else:
                    logger.error('mail not sent')


class ForgotPasswordResource:
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
        logger.info('ForgotPasswordResource')
        global DBSession
        session = DBSession()
        resp.status = falcon.HTTP_404
        resp.location = LOGINSCREEN

        params = req.params
        if not login_forgot_params.check(params):
            logger.info('unauthorized, login forgot params do not have proper format')
        else:
            email = params['email']
            user = session.query(User).filter(User.email == email).first()

            # we always send the same response, no matter if the user exists or not
            resp.status = falcon.HTTP_303
            resp.location = f"{LOGINSCREEN}?checkemail"

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
                if mail(f"""
                Hi {user.name},

                We received a request to reset your password. If it wasn't you, please ignore this message.
                Otherwise, follow this link and select a new password.

                {RESETPASSWORD}?confirmationid={pr.id}

                """, "Password change request", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p):
                    logger.success('mail successfully sent')
                else:
                    logger.error('mail not sent')


class VerifySessionResource:
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
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
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
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
                session.delete(s)
            session.commit()
            logger.success(f'logout authorized for user {s.user.email}')
            resp.status = falcon.HTTP_303
            return
        logger.info('logout unauthorized, session not found or no session cookie present')


class ChoosePasswordResource:
    @falcon.before(max_body(1024))
    def on_post(self, req, resp):
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
    @falcon.before(max_body(0))
    def on_post(self, req, resp, item):
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
    @falcon.before(max_body(0))
    def on_get(self, req, resp):
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
    @falcon.before(max_body(0))
    def on_get(self, req, resp):
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
    for s in session.query(Session):
        logger.info(f"{s.id} {s.created} {s.userid}")
    session.close()
    return True


# https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#foreign-key-support
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


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
