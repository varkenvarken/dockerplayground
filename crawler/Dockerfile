FROM python:3

RUN python -m pip install requests loguru

ENTRYPOINT ["python", "./crawler.py"]

WORKDIR /usr/src/app

COPY crawler/ .
