import falcon

class HealthResource:
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = b'I am healthy'



from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, exc

Base = declarative_base()

class Employee(Base):
    __tablename__ = 'employees'
    id      = Column(Integer, primary_key=True)
    name    = Column(String(50))
    age     = Column(Integer)


from falcon_autocrud.resource import CollectionResource, SingleResource

class EmployeeCollectionResource(CollectionResource):
    model = Employee

class EmployeeResource(SingleResource):
    model = Employee

if __name__ == '__main__':
    import argparse
    from time import sleep
    from wsgiref.simple_server import make_server
    from sys import exit
    from sqlalchemy import create_engine
    import falcon
    from falcon_autocrud.middleware import Middleware


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

    app = falcon.API(
        middleware=[Middleware()],
    )

    app.add_route('/employees', EmployeeCollectionResource(db_engine))
    app.add_route('/employees/{id}', EmployeeResource(db_engine))
    app.add_route('/', HealthResource())

    with make_server('', args.port, app) as httpd:
        print(f"Serving on port {args.port} ...")
        httpd.serve_forever()
