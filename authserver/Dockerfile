FROM python:3

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install falcon PyMySQL PyMySQL[rsa] SQLAlchemy loguru regex gunicorn

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8005", "server:app"]

#HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"]

WORKDIR /usr/src/app

COPY authserver/src src

# so the default reference filelocations will work
COPY authserver/mailtemplates mailtemplates

ENV PYTHONPATH=src
