FROM python:3

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install requests

ENTRYPOINT ["python", "server.py", "-p", "8000"]

#HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"] 

WORKDIR /usr/src/app

COPY crudapp/ .

