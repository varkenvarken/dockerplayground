FROM python:3

RUN python -m pip install mysql-connector-python

WORKDIR /usr/src/app

COPY . .

CMD ["python", "./server.py", "-d", "content", "--loghost", "sqlserver"]


