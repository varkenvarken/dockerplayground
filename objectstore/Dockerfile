FROM python:3

RUN python -m pip install PyMySQL
RUN python -m pip install PyMySQL[rsa]
RUN python -m pip install falcon
RUN python -m pip install SQLAlchemy
RUN python -m pip install falcon-autocrud
RUN python -m pip install falcon-prometheus

ENTRYPOINT ["python", "./objectstore.py", "-d", "mysql+pymysql://dbuser:secret@dbserver_entity/entity", "-r", "4"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:5555/"] 

WORKDIR /usr/src/app

COPY objectstore/ .

