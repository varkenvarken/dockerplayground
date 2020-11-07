# dockerplayground
Playground for creating a general docker based web application with a mixed technology stack

General notes are being documented on [a separate website](https://varkenvarken.github.io/dockerplayground/index.html) and progess is reported on a [blog](https://dockerplayground.michelanders.nl/)

![Docker Image CI](https://github.com/varkenvarken/dockerplayground/workflows/Docker%20Image%20CI/badge.svg)
![Flake8](https://github.com/varkenvarken/dockerplayground/workflows/Flake8/badge.svg)
![CodeQL](https://github.com/varkenvarken/dockerplayground/workflows/CodeQL/badge.svg)

# outline

The application we implement is a simple book collection app, suitable for multiple users. However, that is not what this project is about. We focus here on building a solution with different components that should be independent from each other, scalable and run as docker containers.

This means for example we have a separate database server (MySQL), an authentication server (in Python), a REST based objectstore (using Falcon) a frontend server (Python again) and a reverse proxy (Traefik) to forward incoming requests to the appropriate servers. We will even add metrics collection with prometheus and a dashboard with Grafana. 

# quick start

- prerequisite: have docker up and running on your box
- clone this Git repo
- for a local installation, make sure you have a DNS entry that resolves to your localhost (e.g. myserver.local)
- change the docker-compose.yml to override the FQDN build arg with that same name
- change the contents of the files in the secrets/ folder or override them by setting the enviromment variables SMTP_SERVER SMTP_USER SMTP_PASSWORD (to access the mailserver for sending registration confirmation emails) and ADMIN_USER ADMIN_PASSWORD (to set the admin credentials)
- docker-compose up -d
- browse to https://myserver.local

# current status
![](https://raw.githubusercontent.com/varkenvarken/dockerplayground/master/docs/illustrations/General%20Web%20Application%20Architecture%20-%20Status%2020201107.svg)
