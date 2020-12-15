FROM python:3

# Note that due to autocrud falcon gets downgraded to 1.4.1
RUN python -m pip install --upgrade pip setuptools wheel PyMySQL PyMySQL[rsa] falcon==1.4.1 SQLAlchemy falcon-autocrud falcon-prometheus regex requests loguru

# parameters for database connectivity are stored in environment variables or secrets
ENTRYPOINT ["python", "./objectstore.py", "-r", "4"]

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:5555/health"]

WORKDIR /usr/src/app

COPY objectstore/ .

