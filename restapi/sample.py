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

from sqlalchemy import create_engine
import falcon
from falcon_autocrud.middleware import Middleware

db_engine = create_engine('sqlite:///stuff.db')

Base.metadata.create_all(db_engine)

app = falcon.API(
    middleware=[Middleware()],
)

app.add_route('/employees', EmployeeCollectionResource(db_engine))
app.add_route('/employees/{id}', EmployeeResource(db_engine))

from wsgiref.simple_server import make_server

with make_server('', 5555, app) as httpd:
    print("Serving on port 5555 ...")
    httpd.serve_forever()
