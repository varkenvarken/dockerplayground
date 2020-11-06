FROM python:3

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install PyMySQL PyMySQL[rsa] SQLAlchemy loguru regex

ENTRYPOINT ["python", "server.py", "-d", "/var/lib/sqlite/user.db"]

#HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"] 

WORKDIR /usr/src/app

COPY authserver/ .

