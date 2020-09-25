FROM python:3

RUN python -m pip install PyMySQL
RUN python -m pip install PyMySQL[rsa]
RUN python -m pip install falcon
RUN python -m pip install SQLAlchemy
RUN python -m pip install falcon-autocrud

WORKDIR /usr/src/app

COPY . .

ENTRYPOINT ["python", "./objectstore.py", "-d", "mysql+pymysql://dbuser:secret@dbserver_entity/log_entity"]

