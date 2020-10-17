FROM python:3

# Note that due to autocrud falcon gets downgraded to 1.4.1
RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install PyMySQL
RUN pip install PyMySQL[rsa]
RUN pip install falcon
RUN pip install SQLAlchemy
RUN pip install falcon-autocrud
RUN pip install falcon-prometheus
RUN pip install requests

# parameters for database connectivity are stored in environment variables or secrets
ENTRYPOINT ["python", "./objectstore.py", "-r", "4"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:5555/health"] 

WORKDIR /usr/src/app

COPY objectstore/ .

