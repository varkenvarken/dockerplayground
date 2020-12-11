import os
from sys import stderr, exit
from time import time
from collections import defaultdict as dd
from statistics import stdev, fmean

import requests
from regex import fullmatch, search
from http.cookies import SimpleCookie
from loguru import logger
import regex

logger.remove()
logger.add(stderr, level=os.environ['FUNCTIONALDEBUGLEVEL'] if 'FUNCTIONALDEBUGLEVEL' in os.environ else 'DEBUG')

ADMIN_USER     = os.environ['ADMIN_USER']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
LOGINSCREEN    = os.environ['LOGINSCREEN']
APPLICATION    = os.environ['APPLICATION']
DOMAIN         = os.environ['DOMAIN']
SERVERLOG      = os.environ['SERVERLOG']
PORT           = os.environ['PORT']


class rq:
    def __init__(self, name, method, endpoint, status, params=None, checkheaders=None, checkcookies=None, checkbody=None, annotations=None, variables=None):
        self.name         = name
        self.method       = method
        self.endpoint     = endpoint
        self.status       = status
        self.params       = params if params is not None else dict()
        self.checkheaders = checkheaders
        self.checkcookies = checkcookies
        self.checkbody    = checkbody
        self.annotations  = annotations if annotations is not None else dict()
        self.variables    = variables if variables is not None else dict()
        self.error        = ''
        self.response     = None
        self.jar          = None
        self.testresult   = '-'

    def __str__(self):
        return f'{self.name:30}: {self.testresult:4}, {self.method} {self.endpoint.format(**self.variables)} --> {self.status} ({self.error})'

    def getcookie(self, c):
        if self.jar is not None and c in self.jar:
            return self.jar[c].output(header='').lstrip()
        return None

    def getcookievalue(self, c):
        if self.jar is not None and c in self.jar:
            return t.jar['session'].coded_value
        return None

    def check(self, cookies=None, extraparams=None):
        logger.info(self.name)
        self.testresult = 'fail'
        endpoint = self.endpoint.format(**self.variables)
        logger.info(f'{self.method} {endpoint}')

        if self.method == 'GET':
            r = requests.get(endpoint, params=self.params, allow_redirects=False, cookies=cookies)
        elif self.method == 'POST':
            params = self.params.copy()
            if extraparams is not None:
                params.update(extraparams)
            for k in params:
                params[k] = str(params[k]).format(**self.variables)
                logger.info(f'{k}:{params[k]}')
            r = requests.post(endpoint, data=params, allow_redirects=False, cookies=cookies)
        else:
            raise NotImplementedError
        self.response = r
        logger.info(f'{r.status_code} {r.reason}')
        for h, v in r.headers.items():
            logger.info(f'{h}:{v}')
        if r.status_code != self.status:
            self.error = f'returned status code {r.status_code} != {self.status}'
            return False
        if self.checkheaders is not None:
            for header, re in self.checkheaders:
                if header == 'reason':
                    if not fullmatch(re, r.reason):
                        self.error = f'reason does not match {re} ({r.reason})'
                        return False
                elif not fullmatch(re, r.headers[header]):
                    self.error = f'header {header} does not match {re} ({r.headers[header]})'
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


host = f'http://localhost:{PORT}'


def fetch(re, filename, group=0):
    """
    Return the match in the last line that contains a pattern or None.

    re: a regular expression
    filename: filename that will be opened read only
    group: return the capture group
    """
    result = None
    with open(filename) as f:
        for line in f.readlines():
            if match := regex.search(re, line):
                result = match.group(group)
    return result


MAXD = .05
ITERATIONS = 100

localvars = {}

tests = [
    rq('check /', 'GET', f'{host}', 404),

    rq('check /login', 'GET', f'{host}/login', 405),

    rq('check /login no params', 'POST', f'{host}/login', 303,
        checkheaders=[("Location", rf"{LOGINSCREEN}\?failed")]),

    rq('check /login w. params', 'POST', f'{host}/login', 303,
        params=dict(email=ADMIN_USER, password=ADMIN_PASSWORD, login='Login'),
        checkheaders=[("Location", f"{APPLICATION}")],
        checkcookies=[("session", rf"[0-9a-f]{{32}};\s+Domain={DOMAIN}; Path=/; SameSite=Lax; Secure")],
        annotations={'keepsession': True}),

    rq('verify session', 'POST', f'{host}/verifysession', 200,
        checkbody=[(r'email=(\S+)', 1, ADMIN_USER)],
        annotations={'sessioncookie-sessionid': True}),

    rq('verify stats users', 'POST', f'{host}/stats/users', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats passwordresets', 'POST', f'{host}/stats/passwordresets', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats sessions', 'POST', f'{host}/stats/sessions', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('verify stats pendingusers', 'POST', f'{host}/stats/pendingusers', 200,
        checkbody=[(r'\{"data":', 0, '{"data":')]),

    rq('check /logout', 'POST', f'{host}/logout', 303,
        checkheaders=[("Location", f"{LOGINSCREEN}")],
        checkcookies=[("session", None)],
        annotations={'keepsession': True}),

    rq('verify session expired', 'POST', f'{host}/verifysession', 404,
        annotations={'sessioncookie-sessionid': True}),

    rq('check /register', 'POST', f'{host}/register', 303,
        params=dict(email='testuser@example.org', password=ADMIN_PASSWORD, password2=ADMIN_PASSWORD, name='Testuser', login='Register'),
        checkheaders=[("Location", rf"{LOGINSCREEN}\?pending")],
        annotations={'confirmationid': (r'confirmation id: ([0-9a-f]{32})', SERVERLOG, 1)}),

    rq('confirm registration', 'GET', f'{host}/confirmregistration?confirmationid={{confirmationid}}', 303, variables=localvars,
        checkheaders=[("reason", "See Other")]),

    rq('confirm invalid registration', 'GET', f'{host}/confirmregistration?confirmationid=deadbeefdeadbeefdeadbeefdeadbeef', 303,
        checkheaders=[("reason", "See Other")]),

    rq('check /login forgot', 'POST', f'{host}/forgotpassword', 303,
        params=dict(email='testuser@example.org', login='Forgot'),
        checkheaders=[("Location", rf"{LOGINSCREEN}\?checkemail")],
        annotations={'confirmationid': (r'confirmation id: ([0-9a-f]{32})', SERVERLOG, 1)}),

    rq('confirm resetpassword', 'GET', f'{host}/confirmforgotpassword?confirmationid={{confirmationid}}', 303, variables=localvars,
        checkheaders=[("reason", "See Other")]),

    rq('provide new password', 'POST', f'{host}/choosepassword', 303, variables=localvars,
        params=dict(resetid='{confirmationid}', password=ADMIN_PASSWORD, password2=ADMIN_PASSWORD, choose='Choose'),
        checkheaders=[("reason", "See Other")]),

    rq('check /login (time test) user!', 'POST', f'{host}/login', 303,
        params=dict(email='nonexistinguser@example.org', password=ADMIN_PASSWORD, login='Login'),
        checkheaders=[("Location", rf"{LOGINSCREEN}\?failed")],
        annotations={'checkwait': (r'waiting for (-?\d+\.\d+) seconds', SERVERLOG, 1), 'iterate': ITERATIONS, 'label': 'user'}),

    rq('check /login (time test) pswd!', 'POST', f'{host}/login', 303,
        params=dict(email=ADMIN_USER, password='Secr3t!!@ddd', login='Login'),
        checkheaders=[("Location", rf"{LOGINSCREEN}\?failed")],
        annotations={'checkwait': (r'waiting for (-?\d+\.\d+) seconds', SERVERLOG, 1), 'iterate': ITERATIONS, 'label': 'password'}),

]

failed = False
cookies = None
elapsed = dd(float)
expected = dd(float)
deviation = dd(float)
for t in tests:
    n = 1
    sumval = 0.0
    sumtime = []
    if 'iterate' in t.annotations:
        n = t.annotations['iterate']
    for i in range(n):
        start = time()
        result = t.check(cookies, extraparams={'sessionid': cookies['session']} if 'sessioncookie-sessionid' in t.annotations else None)
        sumtime.append(time() - start)
        print(f'{i+1:3d}/{n:3d}', t, end="\r")
        if not result:
            failed = True
        if 'keepsession' in t.annotations:
            cookies = {'session': t.getcookievalue('session')}
        if 'confirmationid' in t.annotations:
            localvars['confirmationid'] = fetch(*t.annotations['confirmationid'])
        if 'checkwait' in t.annotations:
            sumval += float(fetch(*t.annotations['checkwait']))
    print()
    if 'iterate' in t.annotations:
        mean_elapsed = fmean(sumtime)
        stdev_elapsed = stdev(sumtime)
        mean_expected = sumval / n
        if 'label' in t.annotations:
            elapsed[t.annotations['label']] += mean_elapsed
            expected[t.annotations['label']] += mean_expected
            deviation[t.annotations['label']] += stdev_elapsed
u = elapsed['user']
p = elapsed['password']
du = deviation['user']
dp = deviation['password']
eu = expected['user']
ep = expected['password']
d = u - p
dd = du + dp
deu = abs(u - eu)
dep = abs(p - ep)

if d > dd:
    print(f'failed: variance in timing smaller than difference between non existing user and wrong password {d:.6f} > {dd:.6f}')
    failed = True

if failed:
    exit(1)
