FROM mysql

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install PyMySQL
RUN python3 -m pip install PyMySQL[rsa]

ENV MYSQL_DATABASE logging

WORKDIR /usr/src/app

COPY dbserver_log/sql-scripts/ /docker-entrypoint-initdb.d/

COPY common/dbping.py .

HEALTHCHECK  CMD ["python3", "./dbping.py", "-s", "localhost", "-d", "logging"] 
