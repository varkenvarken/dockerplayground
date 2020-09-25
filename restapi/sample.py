from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String

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
    from wsgiref.simple_server import make_server

    from sqlalchemy import create_engine
    import falcon
    from falcon_autocrud.middleware import Middleware


    parser = argparse.ArgumentParser()
    parser.add_argument('--database', '-d', default='sqlite:///stuff.db',
                        help='Specify alternative directory '
                        '[default: sqlite:///stuff.db]')
    parser.add_argument('port', action='store',
                        default=5555, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 5555]')
    args = parser.parse_args()
    
    db_engine = create_engine(args.database)       # 'sqlite:////absolute/path/to/foo.db'

    Base.metadata.create_all(db_engine)

    app = falcon.API(
        middleware=[Middleware()],
    )

    app.add_route('/employees', EmployeeCollectionResource(db_engine))
    app.add_route('/employees/{id}', EmployeeResource(db_engine))

    with make_server('', args.port, app) as httpd:
        print(f"Serving on port {args.port} ...")
        httpd.serve_forever()
