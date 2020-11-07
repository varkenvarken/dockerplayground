#  server.py, an AAA server
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


from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.parse import urlparse, unquote_plus
import sys
from datetime import datetime
from uuid import uuid4 as guid
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from os import urandom
import os
from regex import compile  # we use an alternative regular expression library here to support unicode classes like \p{L}
from smtp import fetch_smtp_params, mail

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, sessionmaker

from loguru import logger


logger.remove()
logger.add(sys.stderr, level=os.environ['DEBUGLEVEL'] if 'DEBUGLEVEL' in os.environ else 'DEBUG')

# domain to be used in session cookie
DOMAIN              = os.environ['DOMAIN']               # e.g. yourdomain.org
# redirect locations for successful logon
APPLICATION         = os.environ['APPLICATION']          # e.g. /books
LOGINSCREEN         = os.environ['LOGINSCREEN']          # e.g. /books/login.html
# these get used in confirmation emails:
CONFIRMREGISTRATION = os.environ['CONFIRMREGISTRATION']  # e.g. https://server.yourdomain.org/auth/confirmregistration
RESETPASSWORD       = os.environ['RESETPASSWORD']        # e.g. https://server.yourdomain.org/auth/resetpassword

SESSIONID_pattern   = compile(r"[01-9a-f]{32}")                 # 32 hexadecimal lowercase characters
EMAIL_pattern       = compile(r"[^@]+@[^.]+\.[^.]+(\.[^.]+)*")  # rough check: something@subdomain.domain.toplevel  any number of subdomains but cannot start or end with a dot and must contain a domain and a toplevel
PASSWORD_lower      = compile(r"[a-z]")
PASSWORD_upper      = compile(r"[A-Z]")
PASSWORD_digit      = compile(r"[01-9]")
PASSWORD_special    = compile(r"[ !|@#$%^&*()\-_.,<>?/\\{}\[\]]")
NAME_pattern        = compile(r"[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N} ]+")  # letters, marks, digits in any language


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


def allowed_email(s):
    """
    Check if s is a valid email address format.

    This is not an exhaustive check, the final truth is determined by
    whether the email is delivered or not so this check is rather
    permissive.
    """
    if len(s) > 100:  # protect against overly long strings
        return False
    return bool(EMAIL_pattern.fullmatch(s))


def allowed_name(s):
    if len(s) > 100:
        return False
    return bool(NAME_pattern.fullmatch(s))


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


def allowed_password(s):
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
    params = {}
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


Base = declarative_base()


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
    id       = Column(String(34), primary_key=True)  # holds a guid
    created  = Column(DateTime(), default=datetime.now())
    userid   = Column(Integer, ForeignKey('user.id'))
    user     = relationship(User)


class PendingUser(Base):
    __tablename__ = 'pendinguser'
    id          = Column(String(34), primary_key=True)  # holds a guid
    email       = Column(String(100), unique=True)
    name        = Column(String(100))
    password    = Column(String(100))
    created     = Column(DateTime(), default=datetime.now())


class PasswordReset(Base):
    __tablename__ = 'passwordreset'
    id          = Column(String(34), primary_key=True)  # holds a guid
    created     = Column(DateTime(), default=datetime.now())
    userid      = Column(Integer, ForeignKey('user.id'))
    user        = relationship(User)


# we catch exceptions in this method ourselves
# because otherwise they are caught by the server, w.o. a message,
# and nothing is returned. That causes a 502 Bad gateway in Traefik
class MyHTTPRequestHandler(BaseHTTPRequestHandler):

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

    def do_login(self):
        params = self.params
        # verify necessary parameters are present
        if not verify_login_params(params):
            logger.info("/login input parameters not present or not correct")
            self.login_failed()
            return None
        else:
            email = params['email'].lower()  # email param should be present in all login scenarios
            if not allowed_email(email):
                logger.info(f"/login invalid email format [{email[:120]}]")
                self.login_failed()
                return None
            else:
                if params['login'] == 'Login':
                    logger.info('/login login=Login')
                    if not allowed_password(params['password']):
                        logger.info(f"/login invalid password format [{params['password'][:70]}]")
                        self.login_failed()
                        return None
                    user = self.session.query(User).filter(User.email == email).first()
                    if user:
                        logger.info(f"valid user found {user.email}")
                        if checkpassword(params['password'], user.password):
                            self.redirect_header("Login succeeded", APPLICATION)
                            for s in self.session.query(Session).filter(Session.userid == user.id):
                                self.session.delete(s)
                            ns = Session(userid=user.id, id=guid().hex)
                            self.session.add(ns)
                            self.send_session_cookie(ns.id)
                            logger.success(f'user succesfully authenticated {user.email}')
                        else:
                            logger.info(f'user authentication failed for known user {user.email}')
                            self.login_failed()
                    else:
                        logger.info(f'user authentication failed for unknown user {email}')
                        self.login_failed()
                    return None
                elif params['login'] == 'Register':
                    logger.info('/login login=Register')
                    # We always return the same response (and redirect) no matter
                    # whether the email is in use or not or if anything else is wrong
                    # this is to prevent indexing, i.e. checking which email addresses are in use
                    if not allowed_password(params['password']):
                        logger.info(f"invalid password format [{params['password'][:70]}]")
                    elif not allowed_password(params['password2']):
                        logger.info(f"invalid password format [{params['password2'][:70]}]")
                    elif params['password'] != params['password2']:
                        logger.info("passwords are not identical")
                    elif user:
                        logger.info(f'email already in use {user.email}')
                    elif not allowed_name(params['name']):
                        logger.info(f"name not allowed {params['name']}")
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
                    return None
                elif params['login'] == 'Forgot':
                    logger.info('/login login=Forgot')

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

    def do_verifysession(self):
        params = self.params
        # we only allow sessions to be verified by apps running on the same
        # network, i.e. they should not have any X- headers present
        if self.xheaders_present:
            self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
            logger.info('unauthorized, verifysession called from outside')
        # verify that incoming parameters are what we expect
        if not verify_verifysession_params(params):
            self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
            logger.info('unauthorized, sessionid does not have proper format')
        # if the session is known, compose the response with user data
        # TODO add a hard timelimit to the session
        sessionid = params['sessionid']
        for s in self.session.query(Session).filter(Session.id == sessionid):
            logger.success(f'authorized, valid session found: {sessionid} {s.user.email}')
            logger.info(f'email={s.user.email} id={s.user.id} name={s.user.name} superuser={s.user.superuser}')
            self.send_response(HTTPStatus.OK, "valid session")
            return bytes(f'email={s.user.email}\nid={s.user.id}\nname={s.user.name}\nsuperuser={s.user.superuser}', 'utf-8')
        self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
        logger.info(f'unauthorized, no valid session found: {sessionid}')
        return None

    def do_logout(self):
        if len(self.params):
            logger.info('bad request: logout request should not have parameters')
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad request")
            return None
        if 'session' in self.cookie:
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

    def dispatch(self, url):
        dispatch_table = {
            '/login':         self.do_login,
            '/verifysession': self.do_verifysession,
            '/logout':        self.do_logout,
            '/newpassword':   self.do_newpassword
        }
        if url in dispatch_table:
            return dispatch_table[url]()
        return self.do_unknown()

    def do_POST(self):
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
        try:
            global DBSession
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
        except Exception as e:
            logger.exception(e)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return None

    def do_GET(self):
        try:
            fromip = self.headers['X-Forwarded-For'] if 'X-Forwarded-For' in self.headers else 'internal net'
            logger.info(self.address_string())
            logger.info(f'GET from {fromip}')
            logger.info(f'url {self.path}')

            global DBSession
            session = DBSession()
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


if __name__ == '__main__':
    import argparse
    from time import sleep
    from sys import exit
    import socketserver

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', default=8005, type=int, help='application port')
    parser.add_argument('--backoff', '-b', default=2, type=int, help='start seconds to wait on db connection (doubles every try)')
    parser.add_argument('--retries', '-r', default=3, type=int, help='number of times to retry initial database connection')
    parser.add_argument('--database', '-d', default='/usr/src/app/user.db', type=str, help='number of times to retry initial database connection')
    args = parser.parse_args()

    connection = f"sqlite:///{args.database}"

    # this does not open a connection (yet), that will happen on create_all
    db_engine = create_engine(connection, pool_pre_ping=True)

    # we try to connect to the database several times
    waited = 0
    timeout = args.backoff
    retries = args.retries
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
        exit(111)

    username, password = fetch_admin_params()
    global DBSession
    DBSession = sessionmaker(bind=db_engine)
    session = DBSession()
    for s in session.query(User).filter(User.email == username):
        logger.info(f"deleting user {s.email}")
        session.delete(s)
    session.commit()
    ns = User(email=username, password=newpassword(password), name='Administrator', superuser=True)
    session.add(ns)
    logger.info(f"adding admin user {ns.email}")
    session.commit()

    socketserver.TCPServer.allow_reuse_address = True  # on the class! (not the instance)
    with socketserver.TCPServer(("", args.port), MyHTTPRequestHandler) as httpd:
        logger.info(f"serving at port {args.port}")
        httpd.serve_forever()
