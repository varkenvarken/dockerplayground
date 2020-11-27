FROM python:3

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install falcon PyMySQL PyMySQL[rsa] SQLAlchemy loguru regex gunicorn

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8000", "authserver.server:app"]

#HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"]

WORKDIR /usr/src/app

COPY authserver/src .

