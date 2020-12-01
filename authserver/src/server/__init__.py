#  __init__.py, part of the server package
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
The server package implements an authentication server.

It is a WSGI app implemented in falcon and exposes an app variable that can be called from any WSGI server, like gunicorn.

A typical invocation is

    gunicorn -b 0.0.0.0:8005 server:app

On import a sqlite database is initialized and logging is started.

For more information see [the GitHub repo](https://github.com/varkenvarken/dockerplayground/tree/master/authserver)

The following attributes will be initialized to the values defined in the corresponding environment variables

# Attributes

DEBUGLEVEL: can be CRITICAL, ERROR, SUCCESS, INFO, DEBUG, TRACE. Defaults to DEBUG
DATABASE_FILE: path to databse file, default to `user.db
DATABASE_BACKOFF: number of seconds to ait between database connection retries, defaults to 1, doubles every retry.
DATABASE_RETRIES = number of times to retry a database connection. Defaults to 3.
"""

from os import environ
from sys import stderr
import falcon
from loguru import logger
from .server import get_sessionmaker, add_superuser, LoginResource, LogoutResource, VerifySessionResource, RegisterResource, ConfirmRegistrationResource, ForgotPasswordResource, ConfirmForgotPasswordResource, ChoosePasswordResource, StatsResource


logger.remove()
logger.add(stderr, level=environ['DEBUGLEVEL'] if 'DEBUGLEVEL' in environ else 'DEBUG')

DATABASE_FILE    = environ['DATABASE_FILE'] if 'DATABASE_FILE' in environ else 'user.db'
DATABASE_BACKOFF = int(environ['DATABASE_BACKOFF']) if 'DATABASE_BACKOFF' in environ else 1
DATABASE_RETRIES = int(environ['DATABASE_RETRIES']) if 'DATABASE_RETRIES' in environ else 3

app = None

# open the sqlite database and initialize a SQLAlchemy sessionmaker
if get_sessionmaker(f"sqlite:///{DATABASE_FILE}", DATABASE_BACKOFF, DATABASE_RETRIES):
    # make sure the superuser is present in the database
    if add_superuser():
        # initialize the falcon WSGI application
        app = falcon.API()
        # a parameters in form-urlencoded bodies will be added to the request params (just like query params)
        app.req_options.auto_parse_form_urlencoded = True
        app.add_route('/login',                 LoginResource())
        app.add_route('/logout',                LogoutResource())
        app.add_route('/verifysession',         VerifySessionResource())
        app.add_route('/register',              RegisterResource())
        app.add_route('/confirmregistration',   ConfirmRegistrationResource())
        app.add_route('/forgotpassword',        ForgotPasswordResource())
        app.add_route('/confirmforgotpassword', ConfirmForgotPasswordResource())
        app.add_route('/choosepassword',        ChoosePasswordResource())
        app.add_route('/stats/{item}',          StatsResource())
        # TODO add change password functionality
        logger.success('falcon app initialized')
    else:
        logger.critical("could not initialize falcon app")
else:
    logger.critical(f"could not start database {environ['DATABASE_FILE']}")
