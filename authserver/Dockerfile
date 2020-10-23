FROM python:3

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install PyMySQL
RUN pip install PyMySQL[rsa]
RUN pip install SQLAlchemy

ENTRYPOINT ["python", "server.py", "-d", "/var/lib/sqlite/user.db"]

#HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"] 

WORKDIR /usr/src/app

COPY authserver/ .

