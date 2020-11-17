#  authserver, an AAA server
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

import argparse
import socketserver
from os import environ
from sys import stderr

from loguru import logger

from .server import MyHTTPRequestHandler, get_sessionmaker, add_superuser

logger.remove()
logger.add(stderr, level=environ['DEBUGLEVEL'] if 'DEBUGLEVEL' in environ else 'DEBUG')

parser = argparse.ArgumentParser()
parser.add_argument('--port',     '-p', default=8005,                   type=int, help='application port')
parser.add_argument('--backoff',  '-b', default=2,                      type=int, help='start seconds to wait on db connection (doubles every try)')
parser.add_argument('--retries',  '-r', default=3,                      type=int, help='number of times to retry initial database connection')
parser.add_argument('--database', '-d', default='/usr/src/app/user.db', type=str, help='number of times to retry initial database connection')
args = parser.parse_args()

if get_sessionmaker(f"sqlite:///{args.database}", args.backoff, args.retries):
    if add_superuser():
        socketserver.TCPServer.allow_reuse_address = True  # on the class! (not the instance)
        with socketserver.TCPServer(("", args.port), MyHTTPRequestHandler) as httpd:
            logger.info(f"serving at port {args.port}")
            httpd.serve_forever()
else:
    logger.critical("Could not initialize database")
