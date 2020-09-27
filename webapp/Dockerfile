FROM python:3

RUN python -m pip install PyMySQL
RUN python -m pip install PyMySQL[rsa]
RUN python -m pip install prometheus_client

WORKDIR /usr/src/app

ENTRYPOINT ["python", "./webapp.py", "-d", "content", "--loghost", "dbserver_log"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"]

COPY webapp/ .
