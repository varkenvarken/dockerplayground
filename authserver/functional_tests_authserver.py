import os
from sys import stderr

import requests
from regex import fullmatch, search
from http.cookies import SimpleCookie
from loguru import logger

logger.remove()
logger.add(stderr, level=os.environ['DEBUGLEVEL'] if 'DEBUGLEVEL' in os.environ else 'DEBUG')

ADMIN_USER     = os.environ['ADMIN_USER']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
LOGINSCREEN    = os.environ['LOGINSCREEN']
APPLICATION    = os.environ['APPLICATION']
DOMAIN         = os.environ['DOMAIN']


class rq:
    def __init__(self, name, method, endpoint, status, params=None, checkheaders=None, checkcookies=None, checkbody=None, annotations=None):
        self.name         = name
        self.method       = method
        self.endpoint     = endpoint
        self.status       = status
        self.params       = params if params is not None else dict()
        self.checkheaders = checkheaders
        self.checkcookies = checkcookies
        self.checkbody    = checkbody
        self.annotations  = annotations if annotations is not None else dict()
        self.error        = ''
        self.response     = None
        self.jar          = None
        self.testresult   = '-'

    def __str__(self):
        return f'{self.name:30}: {self.testresult:4}, {self.method} {self.endpoint} --> {self.status} ({self.error})'

    def getcookie(self, c):
        if self.jar is not None and c in self.jar:
            return self.jar[c].output(header='').lstrip()
        return None

    def getcookievalue(self, c):
        if self.jar is not None and c in self.jar:
            return t.jar['session'].coded_value
        return None

    def check(self, cookies=None, extraparams=None):
        self.testresult = 'fail'
        if self.method == 'GET':
            r = requests.get(self.endpoint, params=self.params, allow_redirects=False, cookies=cookies)
        elif self.method == 'POST':
            params = self.params.copy()
            if extraparams is not None:
                params.update(extraparams)
            r = requests.post(self.endpoint, data=params, allow_redirects=False, cookies=cookies)
        else:
            raise NotImplementedError
        self.response = r
        if r.status_code != self.status:
            self.error = f'returned status code {r.status_code} != {self.status}'
            return False
        if self.checkheaders is not None:
            for header, regex in self.checkheaders:
                if not fullmatch(regex, r.headers[header]):
                    self.error = f'header {header} does not match {regex} ({r.headers[header]})'
                    return False
        if self.checkcookies is not None:
            self.jar = SimpleCookie()
            if 'Set-Cookie' in r.headers:
                self.jar.load(r.headers['Set-Cookie'])
            for c, r in self.checkcookies:
                v = self.getcookie(c)
                if v is None:
                    if r is not None:
                        self.error = f'cookie {c} not present'
                        return False
                else:
                    regex = f"{c}={r}"
                    if not fullmatch(regex, v):
                        self.error = f'cookie {c} does not match {regex} ({v})'
                        return False
        if self.checkbody is not None:
            for re, group, v in self.checkbody:
                s = search(re, r.text)
                if s is None or s.group(group) != v:
                    self.error = f'text does not contain {re} = {v}'
                    logger.debug(r.text)
                    return False
        self.testresult = 'pass'
        return True


host = 'http://localhost:8005'

tests = [
    rq('check /', 'GET', f'{host}', 404),

    rq('check /login', 'GET', f'{host}/login', 404),

    rq('check /login no params', 'POST', f'{host}/login', 303,
        checkheaders=[("Location", rf"{LOGINSCREEN}\?failed")]),

    rq('check /login w. params', 'POST', f'{host}/login', 303,
        params=dict(email=ADMIN_USER, password=ADMIN_PASSWORD, login='Login'),
        checkheaders=[("Location", f"{APPLICATION}")],
        checkcookies=[("session", rf"[0-9a-f]{{32}};\s+Domain={DOMAIN}; Path=/; SameSite=Lax")],
        annotations={'keepsession': True}),

    rq('verify session', 'POST', f'{host}/verifysession', 200,
        checkbody=[(r'email=(\S+)', 1, ADMIN_USER)],
        annotations={'sessioncookie-sessionid': True}),

    rq('verify stats users', 'POST', f'{host}/stats?users', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats passwordresets', 'POST', f'{host}/stats?passwordresets', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats sessions', 'POST', f'{host}/stats?sessions', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats pendingusers', 'POST', f'{host}/stats?pendingusers', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('check /logout', 'POST', f'{host}/logout', 200,
        checkheaders=[("Location", f"{LOGINSCREEN}")],
        checkcookies=[("session", None)],
        annotations={'keepsession': True}),

    rq('verify session', 'POST', f'{host}/verifysession', 401,
        annotations={'sessioncookie-sessionid': True}),
]


cookies = None
for t in tests:
    result = t.check(cookies, extraparams={'sessionid': cookies['session']} if 'sessioncookie-sessionid' in t.annotations else None)
    print(t)
    if 'keepsession' in t.annotations:
        cookies = {'session': t.getcookievalue('session')}
