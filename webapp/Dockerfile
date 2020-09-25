FROM python:3

RUN python -m pip install mysql-connector-python

WORKDIR /usr/src/app

COPY . .

ENTRYPOINT ["python", "./server.py", "-d", "content"]


