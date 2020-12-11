# dockerplayground
Playground for creating a general docker based web application with a mixed technology stack

General notes are being documented on [a separate website](https://varkenvarken.github.io/dockerplayground/index.html) and progess is reported on a [blog](https://dockerplayground.michelanders.nl/)

![Docker Image CI](https://github.com/varkenvarken/dockerplayground/workflows/Docker%20Image%20CI/badge.svg)
![Flake8](https://github.com/varkenvarken/dockerplayground/workflows/Flake8/badge.svg)
![CodeQL](https://github.com/varkenvarken/dockerplayground/workflows/CodeQL/badge.svg)
![Test Authserver](https://github.com/varkenvarken/dockerplayground/workflows/Test%20Authserver/badge.svg)

# outline

The application we implement is a simple book collection app, suitable for multiple users. However, that is not what this project is about. We focus here on building a solution with different components that should be independent from each other, scalable and run as docker containers.

This means for example we have a separate database server ([MySQL](https://www.mysql.com/)), an authentication server (in [Python](https://www.python.org/)), a REST based objectstore (using [Falcon](https://falconframework.org/)) a frontend server ([NGINX](https://nginx.org/)) and a reverse proxy ([Traefik](https://traefik.io/)) to forward incoming requests to the appropriate servers. We will even add metrics collection with [Prometheus](https://prometheus.io/) and a dashboard with [Grafana](https://grafana.com/).

A bit of a sidequest is the development of an authentication server. The aim here is to develop a server that can do login/user/session management and registration of new users with email verificatiin. And this server should be independent of the rest of the book application so that we can reuse it later. Writing a robust and secure authorizatiin server is not simple and I do not claim to be a security expert but we will carefully check the final implementation against the various checklists of [owasp.org](owasp.org)

# quick start

- prerequisite: have docker up and running on your box
- clone this Git repo
- for a local installation, make sure you have a DNS entry that resolves to your localhost (e.g. myserver.local.domain)
- change the docker-compose.yml to override the FQDN build arg with that same name
- change the contents of the files in the secrets/ folder or override them by setting the enviromment variables, especially
    - SMTP_SERVER, SMTP_USER, SMTP_PASSWORD (to access the mailserver for sending registration confirmation emails) and
    - ADMIN_USER, ADMIN_PASSWORD (to set the admin credentials. They should be a valid email address and a complex enough password respectively)
    - DOMAIN (the name of the domain, e,g local.domain)
    - FQDN (the name of the server traefik is listening on, e.g. myserver.local.domain)
    - CONFIRMREGISTRATION (e.g. https://myserver.local.domain/auth/confirmregistration)
    - RESETPASSWORD=https://myserver.local.domain/auth/confirmforgotpassword

- docker-compose build
- docker-compose up -d
- browse to https://myserver.local.domain

# current status
![](https://raw.githubusercontent.com/varkenvarken/dockerplayground/master/docs/illustrations/General%20Web%20Application%20Architecture%20-%20Status%2020201107.svg)
