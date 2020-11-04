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
import urllib
from urllib.parse import urlparse, unquote_plus
import sys
from datetime import datetime
from uuid import uuid4 as guid

from hashlib import pbkdf2_hmac
from hmac import compare_digest
from os import urandom
import os

from traceback import print_exc

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, sessionmaker

from smtp import fetch_smtp_params, mail


def newpassword(password):
    salt = urandom(16)
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    print(f"{password} + {salt.hex()} -> >{salt.hex() + dk.hex()}<")
    return salt.hex() + dk.hex()


def checkpassword(password, reference):
    salt = bytes.fromhex(reference[:32])
    dk = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    print(f"{password} + {salt.hex()} -> >{salt.hex() + dk.hex()}< == >{reference}<")
    return compare_digest(salt.hex() + dk.hex(), reference)


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

    def do_POST(self):
        for h in self.headers:
            print(h, self.headers[h], flush=True)
        try:
            global DBSession
            session = DBSession()

            c = self.headers.get('Cookie')
            cookie = SimpleCookie()
            if c:
                cookie.load(c)

            content = None

            params = {}
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            if len(body) > 1000:
                self.send_error(HTTPStatus.BAD_REQUEST, "Post request body too large")
                return None
            for p in body.decode('utf-8').split('&'):
                kv = p.split('=', maxsplit=1)
                if kv:
                    k = urllib.parse.unquote_plus(kv[0])
                    v = ''
                    if len(kv) > 1:
                        v = urllib.parse.unquote_plus(kv[1])
                    params[k] = v

# TODO lowercase email (so that you can't squat an email address by changin capitalization
            if self.path == '/login':
                print('login / register /forgot')
                for k in params:
                    print("  ", k, params[k])
                print(flush=True)
                user = session.query(User).filter(User.email == params['email']).first()
                if ('login' not in params) or (params['login'] not in ('Login', 'Register', 'Forgot')):
                    self.send_error(HTTPStatus.BAD_REQUEST, "Not found")
                elif params['login'] == 'Login':
                    print('login')
                    if user:
                        print('valid user found', user.email, user.password)
                        if checkpassword(params['password'], user.password):
                            self.send_response(HTTPStatus.SEE_OTHER, "Login succeeded")
                            self.send_header("Location", "/books")
                            for s in session.query(Session).filter(Session.userid == user.id):
                                print('old session deleted', s.id, s.user.email)
                                session.delete(s)
                            ns = Session(userid=user.id, id=guid().hex)
                            session.add(ns)
                            self.send_session_cookie(ns.id)
                            print('user authenticated', flush=True)
                        else:
                            self.send_response(HTTPStatus.SEE_OTHER, "Login failed")
                            self.send_header("Location", "/books/login.html?failed")
                            self.send_session_cookie(None)
                            print('user authentication failed', flush=True)
                    else:
                        self.send_response(HTTPStatus.SEE_OTHER, "Login failed")
                        self.send_header("Location", "/books/login.html?failed")
                        self.send_session_cookie(None)
                elif params['login'] == 'Register':
                    print('register')
                    # TODO validate email (rough format) and password (complexity)

                    # We always return the same response (and redirect) no matter
                    # whether the email is in use or not, to prevent indexing
                    if user:
                        print('email already in use', flush=True)
                    else:
                        user = session.query(PendingUser).filter(PendingUser.email == params['email']).first()
                        if user:  # we delete previous pending registration to prevent database overfilling
                            # TODO we should make sure that a limited number of emails are sent to the same address
                            print('previous registration not yet confirmed', flush=True)
                            session.delete(user)
                            session.commit()
                        else:
                            print('first registration', flush=True)
                        pu = PendingUser(id=guid().hex, email=params['email'], password=newpassword(params['password']), name=params['name'])
                        session.add(pu)
                        session.commit()
                        user = session.query(PendingUser).filter(PendingUser.email == params['email']).first()
                        for c in PendingUser.__table__.c.keys():
                            print(c, getattr(user, c))
                        u, p, s = fetch_smtp_params()
                        mail(f"""
                        Hi,

                        Please confirm your registration on Book collection.

                        https://server.michelanders.nl/auth/confirmregistration?{pu.id}

                        """,
                             "Confirm your Book collection registration", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p)
                    self.send_response(HTTPStatus.SEE_OTHER, "Registration pending confirmation, email sent to email address")
                    self.send_header("Location", "/books/login.html?pending")
                    self.send_session_cookie(None)
                elif params['login'] == 'Forgot':
                    print('forgot')
                    # TODO validate email (rough format) and password (complexity)

                    # we always send the same response, no matter if the user exists or not
                    self.send_response(HTTPStatus.SEE_OTHER, "Email sent")
                    self.send_header("Location", "/books/login.html?checkemail")
                    self.send_session_cookie(None)

                    user = session.query(User).filter(User.email == params['email']).first()
                    if not user:  # no user found but we are not providing this information
                        print('no user found', flush=True)
                    else:
                        pr = PasswordReset(id=guid().hex, userid=user.id)
                        session.add(pr)
                        session.commit()
                        u, p, s = fetch_smtp_params()
                        mail(f"""
                        Hi,

                        We received a request to reset your password. If it wasn't you, please ignore this message.
                        Otherwise, follow this link and select a new password.

                        https://server.michelanders.nl/auth/resetpassword?{pr.id}

                        """,
                             "Password change request", fromaddr=u, toaddr=user.email, smtp=s, username=u, password=p)

            elif self.path == '/verifysession':
                print('verifysession', flush=True)
                for s in session.query(Session).filter(Session.id == params['sessionid']):
                    print(s.id, s.user.email, flush=True)
                    self.send_response(HTTPStatus.OK, "valid session")
                    content = bytes(f'email={s.user.email}\nid={s.user.id}\nname={s.user.name}\nsuperuser={s.user.superuser}', 'utf-8')
                    print('found', content)
                    break
                if not content:
                    self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
                    print('unauthorized', flush=True)
                else:
                    self.send_response(HTTPStatus.OK, "valid session")
                    print('ok authorized', flush=True)

            elif self.path == '/logout':
                print('logout', flush=True)
                c = self.headers.get('Cookie')
                cookie = SimpleCookie()
                if c:
                    cookie.load(c)
                if 'session' in cookie:
                    print('session', cookie['session'], flush=True)
                    for s in session.query(Session).filter(Session.id == cookie['session'].value):
                        print(s.id, s.user.email, flush=True)
                        session.delete(s)
                        content = bytes(s.user.email, 'utf-8')
                        print('deleted', content)
                        break
                if not content:
                    self.send_response(HTTPStatus.UNAUTHORIZED, "no valid session")
                    print('unauthorized', flush=True)
                else:
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Location", "/books/login.html")
                    print('ok authorized', flush=True)

            elif self.path == '/newpassword':
                # TODO rigid input check (do we have the correct parameters present etc.)
                print('newpassword', flush=True)
                for k in params:
                    print("  ", k, params[k])
                print(flush=True)
                resetuser = session.query(PasswordReset).filter(PasswordReset.id == params['resetid']).first()
                if resetuser:
                    print('ok', flush=True)
                    user = resetuser.user
                    user.password = newpassword(params['password'])
                    session.commit()
                    self.send_response(HTTPStatus.SEE_OTHER, "Password reset successful")
                    self.send_header("Location", "/books/login.html?resetsuccessful")
                    self.send_session_cookie(None)
                else:
                    self.send_response(HTTPStatus.SEE_OTHER, "Password reset failed")
                    self.send_header("Location", "/books/login.html?resetfailed")
                    self.send_session_cookie(None)

            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")

            session.commit()
            if content:
                print('content', content, flush=True)
                self.send_header("Content-type", "text/html; charset=UTF-8")
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
                self.wfile.flush()
                print('done', flush=True)
            else:
                print('no content', flush=True)
                self.end_headers()

            return None
        except Exception as e:
            print('uncaught exception', e, flush=True)
            print_exc(file=sys.stdout)
            print(flush=True)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return None

    def end_headers(self):
        super().end_headers()

    def send_session_cookie(self, session_id):
        cookie = SimpleCookie()
        cookie['session'] = session_id
        cookie['session']['samesite'] = 'Lax'
        cookie['session']['domain'] = 'michelanders.nl'
        cookie['session']['path'] = '/'
        for morsel in cookie.values():
            self.send_header("Set-Cookie", morsel.OutputString())

    def do_GET(self):
        try:
            global DBSession
            session = DBSession()
            # TODO verify/sanitize query parameters before acting upon them w. DB queries!
            url = urlparse(self.path)
            print(url, flush=True)
            if url.path == '/confirmregistration':
                print('confirmation', flush=True)
                user = session.query(PendingUser).filter(PendingUser.id == url.query).first()
                if user:
                    # copy user to User table
                    ns = User(email=user.email, password=user.password, name=user.name)
                    session.add(ns)
                    session.commit()
                    # redirect to login page
                    print('ok', flush=True)
                    self.send_response(HTTPStatus.SEE_OTHER, "Confirmation ok")
                    self.send_header("Location", "/books/login.html?confirmed")
                    self.end_headers()
                else:  # no pending confirmation or expired, redirect to login page
                    print('expired', flush=True)
                    self.send_response(HTTPStatus.SEE_OTHER, "Confirmation link expired")
                    self.send_header("Location", "/books/login.html?expired")
                    self.end_headers()
                # TODO clean pending users with same email? (note: only expired)
            if url.path == '/resetpassword':
                print('resetpassword', flush=True)
                pr = session.query(PasswordReset).filter(PasswordReset.id == url.query).first()
                if pr:
                    print('ok', flush=True)
                    # note that we do not create a session
                    self.send_response(HTTPStatus.SEE_OTHER, "Reset request ok")
                    self.send_header("Location", f"/books/login.html?choosepassword={pr.id}")
                    self.end_headers()
                else:  # no pending confirmation or expired, redirect to login page
                    print('expired', flush=True)
                    self.send_response(HTTPStatus.SEE_OTHER, "Confirmation link expired")
                    self.send_header("Location", "/books/login.html?expired")
                    self.end_headers()
                # TODO clean pending users with same email? (note: only expired)
            else:
                print('not found', flush=True)
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                self.end_headers()

            return None
        except Exception as e:
            print('uncaught exception', e, flush=True)
            print_exc(file=sys.stdout)
            print(flush=True)
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
            print(e)
            print(f"Database connection refused trial {i}/{retries}, now waiting {timeout} seconds ...")
            sleep(timeout)
            waited += timeout
            timeout *= 2
            continue
    else:
        print(f"No database connections after {retries} tries ({waited} seconds)")
        exit(111)

    username, password = fetch_admin_params()
    global DBSession
    DBSession = sessionmaker(bind=db_engine)
    session = DBSession()
    for s in session.query(User).filter(User.email == username):
        print(s.id, s.email)
        session.delete(s)
    session.commit()
    ns = User(email=username, password=newpassword(password), name='Administrator', superuser=True)
    session.add(ns)
    session.commit()

    socketserver.TCPServer.allow_reuse_address = True  # on the class! (not the instance)
    with socketserver.TCPServer(("", args.port), MyHTTPRequestHandler) as httpd:
        print("serving at port", args.port)
        httpd.serve_forever()
