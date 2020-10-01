FROM python:3

ENTRYPOINT ["python", "-m", "http.server"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000/"] 

WORKDIR /usr/src/app

COPY crudapp/ .

