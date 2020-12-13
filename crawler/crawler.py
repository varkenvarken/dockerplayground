#  crawler.py
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

import os
from sys import stderr
from http.cookies import SimpleCookie
import json
from datetime import datetime
from base64 import b64encode
import requests
from loguru import logger
import warnings

"""
Crawler.py adds missing values to a book collection.

Currently it gets the additional values from www.openlibrary.org
"""

showwarning_ = warnings.showwarning


def showwarning(message, *args, **kwargs):
    logger.warning(message)
    # showwarning_(message, *args, **kwargs)


warnings.showwarning = showwarning

logger.remove()
logger.add(stderr, level='DEBUG')


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

AUTHSERVER = getvar('AUTHSERVER', 'http://dockerplayground_authserver_1:8005')
OBJECTSTORE = getvar('OBJECTSTORE', 'http://dockerplayground_objectstore_1:5555')

def datetimeencoder(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()


def fetch_crawler_credentials():
    """
    Get crawler credentials from file or environment.

    Environment variables overrule variables in files.

    Returns:
        tuple(crawler_user, crawler_password)

    Environment vars:

    - :attr:`CRAWLER_USER_FILE` filename of file containing a super user username (valid email address)
    - :attr:`CRAWLER_USER` username (valid email address) of a super user, will override CRAWLER_USER_FILE
    - :attr:`CRAWLER_PASSWORD_FILE` filename of file containing password in plaintext
    - :attr:`CRAWLER_PASSWORD` password in plaintext, will override CRAWLER_PASSWORD_FILE

    """
    env = {}
    for var in ('CRAWLER_USER', 'CRAWLER_PASSWORD'):
        if var in os.environ and os.environ[var].strip() != '':
            env[var] = os.environ[var]
        else:
            varf = var + '_FILE'
            if varf in os.environ:
                with open(os.environ[varf]) as f:
                    env[var] = f.read().strip()
            else:
                raise KeyError(f'{var} and {varf} not defined in environment')

    return env['CRAWLER_USER'], env['CRAWLER_PASSWORD']


def getcookievalue(jar, c):
    if jar is not None and c in jar:
        return jar['session'].coded_value
    return None


def login(user, password):
    params = dict(email=user, password=password, login='Login')
    try:
        r = requests.post(f'{AUTHSERVER}/login', data=params, allow_redirects=False, verify=False)
        logger.info(r)
        jar = SimpleCookie()
        if 'Set-Cookie' in r.headers:
            jar.load(r.headers['Set-Cookie'])
            return getcookievalue(jar, 'session')
    except requests.exceptions.RequestException as e:
        logger.error(f'could not connect to authserver at {AUTHSERVER}/login : {e}')
    return None


def getbookstoupdate(sessionid):
    params = {'isedited': 0, 'isamended': 0}
    try:
        response = requests.get(f"{OBJECTSTORE}/books", params=params, cookies={'session': sessionid}, allow_redirects=False, verify=False)
        logger.info(response)
        logger.info(response.text)
        return json.loads(response.text)
    except:
        logger.error(f'could not connect to objectstore at {OBJECTSTORE}/books')
    return None

def getbookdatafromopenlibrary(isbn):
    logger.info(f'isbn {isbn}')
    response = requests.get(f"https://openlibrary.org/isbn/{isbn}.json")
    logger.info(f'status {response.status_code}')
    if response.status_code == 404:
        return None
    return response.json()

def getworkdatafromopenlibrary(isbn):
    logger.info(f'isbn {isbn}')
    response = requests.get(f"https://openlibrary.org/isbn/{isbn}.json")
    logger.info(f'status {response.status_code}')
    if response.status_code == 404:
        return None
    return response.json()


def getauthordatafromopenlibrary(book):
    authorid = None
    if 'authors' in book:
        authorid = book['authors'][0]['key']
        logger.info(f'authorid {authorid}')
        response = requests.get(f"https://openlibrary.org/{authorid}.json")
        logger.info(f'status {response.status_code}')
        if response.status_code == 404:
            return None
        return response.json()
    elif 'works' in book:
        key = book['works'][0]['key']
        logger.info('no authors key, so trying works key')
        response = requests.get(f"https://openlibrary.org{key}.json")
        logger.info(f'status {response.status_code}')
        if response.status_code == 404:
            return None
        work = response.json()
        if 'authors' in work:
            authorid = work['authors'][0]['author']['key']
            logger.info(f'authorid {authorid}')
            response = requests.get(f"https://openlibrary.org/{authorid}.json")
            logger.info(f'status {response.status_code}')
            if response.status_code == 404:
                return None
            return response.json()
    else:
        logger.info('no author found')



def getcoverfromopenlibrary(coverid):
    logger.info(f'coverid {coverid}')
    response = requests.get(f"https://covers.openlibrary.org/b/id/{coverid}-L.jpg")
    logger.info(f'status {response.status_code}')
    if response.status_code == 404:
        return None
    return response


def updatebook(bookid, data, sessionid):
    logger.info(data)
    try:
        response = requests.put(f"{OBJECTSTORE}/books/{bookid}", json=data, cookies={'session': sessionid}, verify=False)
        logger.info(f'status {response.status_code}')
        logger.info(response)
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f'could not connect to objectstore at {OBJECTSTORE}/books/{bookid} : {e}')
    return None


def addcoverart(endpoint, data, type, sessionid):
    try:
        response = requests.post(f"{OBJECTSTORE}/images", json={'data': b64encode(data), 'type': type}, cookies={'session': sessionid}, verify=False)
        logger.info(f'status {response.status_code}')
        logger.info(response.text)
        return json.loads(response.text)['data']['id']
    except requests.exceptions.RequestException as e:
        logger.error(f'could not connect to objectstore at {OBJECTSTORE}/images : {e}')
    return None


if __name__ == '__main__':
    import argparse
    from time import sleep

    parser = argparse.ArgumentParser()
    parser.add_argument('--sleep', '-s', default=120, type=int, help='seconds to sleep between update runs')
    args = parser.parse_args()

# how are we going to do this w.o. a webserver?
#   prometheus = PrometheusMiddleware()

    running = True
    while running:
        logger.info('starting crawler run')
        user, password = fetch_crawler_credentials()  # login every run otherwise session will time out
        session = login(user, password)
        if session:
            logger.info(f'session {session}')
            # for the healthcheck we might touch a file?
            books = getbookstoupdate(session)
            if books:
                n = len(books['data'])
                logger.info(f'{n} books to update')
                for book in books['data']:
                    if book['isbn'] is not None and book['isbn'] != "":
                        data = getbookdatafromopenlibrary(book['isbn'])
                        logger.info(data)
                        if data is not None:
                            if 'covers' in data:
                                r = getcoverfromopenlibrary(data['covers'][0])
                                if r:
                                    logger.info('storing coverart')
                                    index = addcoverart(r.content, 'jpg', session)
                                    if index is not None:
                                        book['coverart'] = index
                            # get author data
                            authordata = getauthordatafromopenlibrary(data)
                            logger.info(authordata)
                            book['author'] = authordata['name']
                            book['publisher'] = data['publishers'][0]
                            book['title'] = data['title']
                            book['isamended'] = True
                            book['amended'] = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
                            response = updatebook(book['id'], book, session)
                    else:
                        logger.info('empty isbn')
        logger.info(f'sleeping for {args.sleep} seconds')
        sleep(args.sleep)   # or we could run everything from cron?
