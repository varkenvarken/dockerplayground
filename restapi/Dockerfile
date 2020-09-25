FROM python:3

RUN python -m pip install PyMySQL
RUN python -m pip install PyMySQL[rsa]
RUN python -m pip install falcon
RUN python -m pip install SQLAlchemy
RUN python -m pip install falcon-autocrud

WORKDIR /usr/src/app

COPY restapi .

ENTRYPOINT ["python", "./sample.py", "-d", "mysql+pymysql://dbuser:secret@dbserver/log_db"]


