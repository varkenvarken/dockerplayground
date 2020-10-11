import sys
from datetime import date,datetime
from base64 import b64decode,b64encode
import falcon
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Date, DateTime, Numeric, Boolean, LargeBinary, exc
from falcon_autocrud.resource import CollectionResource, SingleResource

def convert2b64(ob):
    for k,v in ob.items():
        if type(v) == bytes:
            ob[k] = str(b64encode(v),'UTF-8')
        elif type(v) == dict:
            ob[k] = convert2b64(v)
        elif type(v) == list:
            for i,el in enumerate(v):
                if type(el) == dict:
                    v[i] = convert2b64(el)
    return ob

def firstbytes(ob):
    for k,v in ob.items():
        if type(v) == bytes:
            return v
        elif type(v) == dict:
            b = firstbytes(v)
            if b is not None: return b
        elif type(v) == list:
            for i,el in enumerate(v):
                if type(el) == dict:
                    b = firstbytes(el)
                    if b is not None: return b
    return None

class HealthResource:
    """
    A static resource to serve a Docker healthcheck.
    """
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = b'I am healthy'

Base = declarative_base()


class Book(Base):
    __tablename__ = 'books'
    id          = Column(Integer, primary_key=True)
    # TODO add owner
    title       = Column(String(100))
    author      = Column(String(50))
    isbn        = Column(String(15))  # either 10 or 13
    publisher   = Column(String(50))
    published   = Column(Date(), nullable=True)  #default=date(1600,1,1))
    value       = Column(Numeric(8,2), default=0)   # an estimate, currency is supposed to be EUR
    created     = Column(DateTime(), default=datetime.now())
    coverart    = Column(String(150)) # a URL
    isamended   = Column(Boolean(), default=False)   # True is bot has amended any value
    amended     = Column(DateTime(), default=datetime.now())
    isedited    = Column(Boolean(), default=False)   # True if person has overruled bot amendation
    edited      = Column(DateTime(), default=datetime.now())
    
class BookCollectionResource(CollectionResource):
    model = Book


class BookResource(SingleResource):
    model = Book

class Image(Base):
    __tablename__ = 'images'
    id         = Column(Integer, primary_key=True)
    data       = Column(LargeBinary, nullable=False)
    type       = Column(String(10), nullable=True)   # jpg, png, ... might be null or empty
    annotation = Column(String(100), nullable=True)   # whatever you like
    created    = Column(DateTime(), default=datetime.now())

class ImageCollectionResource(CollectionResource):
    model = Image
    
    def before_post(self, req, resp, db_session, resource, *args, **kwargs):
        # Anything you do with db_session is in the same transaction as the
        # resource creation.  Resource is the new resource not yet added to the
        # database.
        self.original_data = resource.data
        resource.data = b64decode(bytes(resource.data,'UTF-8'))
        
    def after_post(self, req, resp, new, *args, **kwargs):
        # 'new' is the created SQLAlchemy instance
        new.data = self.original_data

class ImageResource(SingleResource):
    model = Image

# TODO this is NOT the way to do it
class CORSComponent:
    def process_response(self, req, resp, resource, req_succeeded):
        resp.set_header('Access-Control-Allow-Origin', '*')

        if (True  #req_succeeded
#            and req.method in ('OPTIONS', 'GET', 'PATCH', 'POST', 'DELETE', 'PUT')
#            and req.get_header('Access-Control-Request-Method')
        ):
            # NOTE(kgriffs): This is a CORS preflight request. Patch the
            #   response accordingly.

            allow = resp.get_header('Allow')
            resp.delete_header('Allow')

            allow_headers = req.get_header(
                'Access-Control-Request-Headers',
                default='*'
            )

            resp.set_headers((
                ('Access-Control-Allow-Methods', 'GET, PATCH, POST, DELETE, PUT'),
                ('Access-Control-Allow-Headers', allow_headers),
                ('Access-Control-Max-Age', '86400'),  # 24 hours
                ('Access-Control-Allow-Origin', '*'),
            ))


class JSONBinary:
    def process_response(self, req, resp, resource, params):
        #print(req.context, file=sys.stderr)
        if 'result' in req.context:
            req.context['result'] = convert2b64(req.context['result'])
        #print(req.context, file=sys.stderr)

class RawData:
    def process_response(self, req, resp, resource, params):
        print('query_string', req.query_string, flush=True)
        if req.query_string=='raw':
            try:
                resp.body = b64decode(bytes(req.context['result']['data']['data'],'UTF-8'))
            except KeyError:
                pass

if __name__ == '__main__':
    import argparse
    from time import sleep
    from wsgiref.simple_server import make_server
    from sys import exit
    from os import environ
    from sqlalchemy import create_engine
    import falcon
    from falcon_autocrud.middleware import Middleware
    from falcon_prometheus import PrometheusMiddleware

    password = environ['MYSQL_ROOT_PASSWORD'] if 'MYSQL_ROOT_PASSWORD' in environ else None
    database = environ['MYSQL_DATABASE'] if 'MYSQL_DATABASE' in environ else 'default'
    user = environ['MYSQL_USER'] if 'MYSQL_USER' in environ else 'default'
    server = environ['MYSQL_SERVER'] if 'MYSQL_SERVER' in environ else 'localhost'
    if password is None and 'MYSQL_ROOT_PASSWORD_FILE' in environ:
        with open(environ['MYSQL_ROOT_PASSWORD_FILE']) as f:
            password = f.read().strip()
    connection = f"mysql+pymysql://{user}:{password}@{server}/{database}"

    parser = argparse.ArgumentParser()
    parser.add_argument('--retries', '-r', default=3, type=int, help='number of times to retry initial database connection')
    parser.add_argument('--backoff', '-b', default=2, type=int, help='start seconds to wait on db connection (doubles every try)')
    parser.add_argument('--port', '-p', default=5555, type=int, help='application port')
    args = parser.parse_args()

    # this does not open a connection (yet)
    db_engine = create_engine(connection, pool_pre_ping=True)       # 'sqlite:////absolute/path/to/foo.db'

    waited = 0
    timeout = args.backoff
    retries = args.retries
    for i in range(1,retries):
        try:
            Base.metadata.create_all(db_engine)
            break
        except:
            print(f"Database connection refused trial {i}/{retries}, now waiting {timeout} seconds ...")
            sleep(timeout)
            waited += timeout
            timeout *= 2
            continue
    else:
        print(f"No database connections after {retries} tries ({waited} seconds)")
        exit(111)

    prometheus = PrometheusMiddleware()
    app = falcon.API(  #does not work in falcon 2.0 cors_enable=True,   # see https://falcon.readthedocs.io/en/latest/api/cors.html
        middleware=[CORSComponent(), RawData(), Middleware(), JSONBinary(), prometheus],
    )

    app.add_route('/books', BookCollectionResource(db_engine))
    app.add_route('/books/{id}', BookResource(db_engine))
    app.add_route('/images', ImageCollectionResource(db_engine))
    app.add_route('/images/{id}', ImageResource(db_engine))
    app.add_route('/health', HealthResource())
    app.add_route('/metrics', prometheus)

    with make_server('', args.port, app) as httpd:
        print(f"Serving on port {args.port} ...", file=sys.stderr)
        httpd.serve_forever()
