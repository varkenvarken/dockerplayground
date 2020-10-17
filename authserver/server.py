from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
from http.cookies import SimpleCookie
import urllib
import sys
from datetime import datetime
from uuid import uuid4 as guid
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, Date, DateTime, Boolean
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id          = Column(Integer, primary_key=True)
    email       = Column(String(100))
    password    = Column(String(50))
    created     = Column(DateTime(), default=datetime.now())
    active      = Column(Boolean(), default=True)
    accessed    = Column(DateTime(), default=datetime.now())

class Session(Base):
    __tablename__ = 'session'
    id       = Column(String(34), primary_key=True)  # holds a guid
    created  = Column(DateTime(), default=datetime.now())
    userid   = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_HEAD(self):
        print('do_HEAD')
        do_POST(self)

    def do_POST(self):

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
            kv = p.split('=',maxsplit=1)
            if kv:
                k = urllib.parse.unquote(kv[0])
                v = ''
                if len(kv)>1:
                    v = urllib.parse.unquote(kv[1])
                params[k] = v

        if self.path == '/login':

            user = session.query(User).filter(User.email==params['email']).first()
            if user:
                print('valid user found', user.email, user.password)
                self.send_response(HTTPStatus.SEE_OTHER, "Login succeeded")
                self.send_header("Location","/books")
                for s in session.query(Session).filter(Session.userid == user.id):
                    print(s.id, s.user.email)
                    session.delete(s)
                ns = Session(userid=user.id, id=guid().hex)
                session.add(ns)
                self.send_session_cookie(ns.id)
            else:
                self.send_response(HTTPStatus.SEE_OTHER, "Login failed")
                self.send_header("Location","/books/login.html")
                self.send_session_cookie(None)

        elif self.path == '/verifysession':
            print('verifysession', flush=True)
            for s in session.query(Session).filter(Session.id == params['sessionid']):
                print(s.id, s.user.email, flush=True)
                self.send_response(HTTPStatus.OK, "valid session")
                content = bytes(s.user.email, 'utf-8')
                print('found',content)
                break
            if not content:
                self.send_response(HTTPStatus.UNAUTHORIZED,"no valid session")
                print('unauthorized', flush=True)
            else:
                self.send_response(HTTPStatus.OK,"valid session")
                print('ok authorized', flush=True)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        session.commit()
        if content:
            print('content', content, flush=True)
            self.send_header("Content-type", "text/html; charset=UTF-8")
            self.send_header("Content-Length", len(content))
            #self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            try:
                self.wfile.write(content)
            except Exception as e:
                print(e, flush=true)
            print('done', flush=True)
            self.wfile.flush()
        else:
            print('no content', flush=True)
            self.end_headers()
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

if __name__ == '__main__':
    import argparse
    from time import sleep
    from sys import exit
    import socketserver

    parser = argparse.ArgumentParser()
    parser.add_argument('--port',     '-p', default=8005, type=int, help='application port')
    parser.add_argument('--backoff',  '-b', default=2,    type=int, help='start seconds to wait on db connection (doubles every try)')
    parser.add_argument('--retries',  '-r', default=3,    type=int, help='number of times to retry initial database connection')
    parser.add_argument('--database', '-d', default='/usr/src/app/user.db',    type=str, help='number of times to retry initial database connection')
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

    global DBSession
    DBSession = sessionmaker(bind=db_engine)
    session = DBSession()
    new_user = User(email='jaapaap',password='secret')
    session.merge(new_user)
    session.commit()

    socketserver.TCPServer.allow_reuse_address = True  # on the class! (not the instance)
    with socketserver.TCPServer(("", args.port), MyHTTPRequestHandler) as httpd:
        print("serving at port", args.port)
        httpd.serve_forever()
