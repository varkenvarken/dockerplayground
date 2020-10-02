from datetime import date,datetime
import falcon
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Date, DateTime, Numeric, Boolean, exc
from falcon_autocrud.resource import CollectionResource, SingleResource

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


if __name__ == '__main__':
    import argparse
    from time import sleep
    from wsgiref.simple_server import make_server
    from sys import exit
    from sqlalchemy import create_engine
    import falcon
    from falcon_autocrud.middleware import Middleware
    from falcon_prometheus import PrometheusMiddleware


    parser = argparse.ArgumentParser()
    parser.add_argument('--database', '-d', default='sqlite:///stuff.db',
                        help='Specify alternative directory '
                        '[default: sqlite:///stuff.db]')
    parser.add_argument('--retries', '-r', default=3, type=int, help='number of times to retry initial database connection')
    parser.add_argument('--backoff', '-b', default=2, type=int, help='start seconds to wait on db connection (doubles every try)')
    parser.add_argument('--port', '-p', default=5555, type=int, help='application port')
    args = parser.parse_args()

    # this does not open a connection (yet)
    db_engine = create_engine(args.database, pool_pre_ping=True)       # 'sqlite:////absolute/path/to/foo.db'

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
        middleware=[CORSComponent(), Middleware(), prometheus],
    )

    app.add_route('/books', BookCollectionResource(db_engine))
    app.add_route('/books/{id}', BookResource(db_engine))
    app.add_route('/health', HealthResource())
    app.add_route('/metrics', prometheus)

    with make_server('', args.port, app) as httpd:
        print(f"Serving on port {args.port} ...")
        httpd.serve_forever()
