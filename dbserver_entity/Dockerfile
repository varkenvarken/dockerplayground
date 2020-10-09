FROM mysql

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install PyMySQL
RUN python3 -m pip install PyMySQL[rsa]

# default database, can be replaced in docker-compose
ENV MYSQL_DATABASE default

WORKDIR /usr/src/app

COPY dbserver_entity/sql-scripts/ /docker-entrypoint-initdb.d/

COPY common/dbping.py .

HEALTHCHECK CMD ["python3", "./dbping.py"] 
