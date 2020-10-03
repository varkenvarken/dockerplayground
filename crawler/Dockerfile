FROM python:3

RUN python -m pip install requests

ENTRYPOINT ["python", "./crawler.py", "-r", "http://objectstore:5555"]

WORKDIR /usr/src/app

COPY crawler/ .
