FROM python:3

RUN python -m pip install PyMySQL
RUN python -m pip install PyMySQL[rsa]
RUN python -m pip install falcon
RUN python -m pip install SQLAlchemy
RUN python -m pip install falcon-autocrud
RUN python -m pip install falcon-prometheus

# pass password via environment variable (if non-empty) or file (passed as a secret)
ENTRYPOINT ["python", "./objectstore.py", "-d", "mysql+pymysql://dbuser:$${MYSQL_ROOT_PASSWORD:-`cat $$MYSQL_ROOT_PASSWORD_FILE`}@dbserver_entity/entity", "-r", "4"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:5555/health"] 

WORKDIR /usr/src/app

COPY objectstore/ .

