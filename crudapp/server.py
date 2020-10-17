from http.server import SimpleHTTPRequestHandler
from http import HTTPStatus
from http.cookies import SimpleCookie
import urllib
import sys
from datetime import datetime
from uuid import uuid4 as guid
import requests
import re

unrestricted = re.compile(r'(/login.html)|(/javascript/.*\.js)|(/css/.*\.css)')

class MyHTTPRequestHandler(SimpleHTTPRequestHandler):

    def do_HEAD(self):
        if self.verify_session():
            super().do_HEAD()
        else:
            self.send_response(HTTPStatus.SEE_OTHER, "Login failed")
            self.send_header("Location","/books/login.html")
            self.end_headers()
        return None

    def do_GET(self):
        print(self.path, flush=True)
        if self.verify_session():
            print('session verified', flush=True)
            super().do_GET()
        else:
            print('session not verified', flush=True)
            self.send_response(HTTPStatus.SEE_OTHER, "Login failed")
            self.send_header("Location","/books/login.html")
            self.end_headers()
        return None

    def unrestricted_path(self):
        return bool(unrestricted.match(self.path))

    def verify_session(self):
        try:
            if self.unrestricted_path():
                return True
            c = self.headers.get('Cookie')
            cookie = SimpleCookie()
            if c:
                cookie.load(c)
            if 'session' in cookie:
                print('verify session', cookie['session'], flush=True)
                r = requests.post('http://authserver:8005/verifysession', data = {'sessionid':cookie['session'].value})
                print('status_code', r.status_code, flush=True)
                print(r.content, flush=True)
                return r.status_code == 200
        except Exception as e:
            print(e, flush=True)
        return False    

if __name__ == '__main__':
    import argparse
    import socketserver

    parser = argparse.ArgumentParser()
    parser.add_argument('--port',     '-p', default=8080, type=int, help='application port')
    args = parser.parse_args()

    socketserver.TCPServer.allow_reuse_address = True  # on the class! (not the instance)
    with socketserver.TCPServer(("", args.port), MyHTTPRequestHandler) as httpd:
        print("serving at port", args.port)
        httpd.serve_forever()

