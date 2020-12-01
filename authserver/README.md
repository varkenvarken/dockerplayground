# Authserver
## Introduction
Authserver is a simple authentication server. It is the result of my attempt at gaining insight in how to develop a secure authentication server that can function as an application independent authentication backend.

It is very much a work in progress and I certainly would not advise to run it in any kind of production environment that faces the internet but my goal is to make it as robust and secure as possible. To that end I will try to provide proper documentation and continuous integration that includes security scanning and code analysis (think [ZAProxy](https://www.zaproxy.org/) and [Bandit](https://pypi.org/project/bandit/) for example).

This readme file tries to give an high level overview of the functionality and how to install Authserver and I hope to provide more detailed documentation (in the source) in the near future, especially on implementation decisions.

## Functionality
Authserver is an authentication backend: this means it maintains a database of user information and sessions and provides web services to access these.

A solution that needs an authentication backend will need to provide HTML pages with things like logon and registration forms and those forms can refer the web services provided by Authserver.

Authserver provides just a single authentication method: username/password, but is also provides the functionality to register new users (and have them confirm their registration via email) and have them request a new password if they forget.

Authserver also provides session management: users who successfully authenticate when logging in will create a session and Authserver provides a webservice that can be used by an application back-end to verify if a session is still active. It also expires sessions that are stale or when a user logs out.

Authserver is part of a larger GitHub project called [dockerplayground](https://github.com/varkenvarken/dockerplayground) and in this project it runs inside it own docker container and serves as authentication back-end for a and application that lets user manage their book collection. This application consists of a front end that provides (among other things) logon and registration facilities that communicate with Authserver and a back-end that verifies whether a user has a valid session.

## Table of contents
[Authserver](#authserver)

[Installation](#installation)

[Prerequisites](#prerequisites)

[Download](#download)

[Test](#test)

[Environment variables](#environment-variables)

[Email templates](#email-templates)

[Example docker-compose.yml](#example-docker-composeyml)

[Usage](#Usage)

[Solution Design](#solution-design)

[Available endpoints](#available-endpoints)

[Source Documentation](#source-documentation)

# Installation
## Prerequisites
Authserver is designed and tested on Python 3.8

It comes with a Dockerfile as it is intended to run inside a Docker container.

For local testing and development, requirements are listed in the file `requirements.txt`

## Download
Authserver is part of a larger GitHub project called [dockerplayground](https://github.com/varkenvarken/dockerplayground).

You can download or clone the repository in the usual manner and once you have installed it, just make sure that you are inside the toplevel dockerplayground directory to perform the next steps.

## Test
To test Authserver locally:

    cd dockerplayground
    pip3 install -r requirements.txt
    make testauthserver
This will start the server, perform several unit tests and functional tests and the exit.

The results from the unit tests are saved in `authserver/unittest_report.txt` and coverage is reported in `authserver/coverage_report.txt`. A browsable version of the coverage is available in `authserver/htmlcov/index.html`.

Note that because Authserver is designed to be part of a larger solution it is expected to run inside a docker container as a service in a more complete deployment. The [docker-compose.yml file](https://github.com/varkenvarken/dockerplayground/blob/master/docker-compose.yml) shows such an example, some details a highlighted [below](#example-docker-composeyml).

## Environment variables
The behavior of Authserver is largely controlled by a number of environment variables.

### Database configuration
Authserver uses an sqlite databae to store user information and sessions. The database connection is configured using the following variables:

- DATABASE_FILE
> the name of the database file, e.g. `/var/lib/sqlite/user.db` (default `user.db`).
- DATABASE_BACKOFF
> the number of seconds to wait between connection attempts in seconds (default 1, will double on every attempt).
- DATABASE_RETRIES
> the number of times to retry connecting to the database (default 3).

### URLs
After submitting a form to one of its endpoints, Authserver will provide a redirection URL in its response (in the `Location` header) depending the success or failure of the activity. Likewise, you will need to provide the links to be used in confirmation emails that are sent upon registration or password resets:

- DOMAIN (e.g. `yourdomain.org`)
> domain to be used in session cookies
- APPLICATION (e.g. `/books`)
> url to redirect to after a successful login.
- LOGINSCREEN (e.g. `/books/login.html`)
> url to redirect to after a unsuccessful login or after a password reset or registration.
- CONFIRMREGISTRATION (typically `https://server.yourdomain.org/auth/confirmregistration`)
> url to use in emails, see [Available endpoints](#Available endpoints) below
- RESETPASSWORD (typically `https://server.yourdomain.org/auth/confirmforgotpassword`)
> url to use in emails, see [Available endpoints](#Available endpoints) below

### Admin user
Authserver will configure itself the first time it is run with a single superuser account

- ADMIN_USER (e.g. `yourname@yourdomain.org`)
> All other users are expected to supply valid email addresses but the admin user is the exception.
- ADMIN_PASSWORD (e.g. `Secr3t!!`)
> this must be conform password complexity requirements (at least 8 chars, at least 1 upper, 1 lower, 1 special and 1 digit)

### SMTP server
The confirmation mails that will be send need an SMTP server. This SMTP mail may require authentication as well.

- SMTP_SERVER (e.g. `smtpserver.local`)
> hostname or ipadress of the SMTP server
- SMTP_USER (e.g. `relayuser1`)
> user
- SMTP_PASSWORD (e.g. `mailsecr3t`)
> password

Note that the LOGINSCREEN url might be appended with `?error`, `?checkemail` or `?choosepassword=<id>` depending on the circumstances. This might be used by the frontend application to give some feedback to the user.

### Application name
- WEBSITE (e.g. `Book Collection`)
> used in the email templates used for confirmation mails. This is typically *not* a URL.

### Time limits
- SOFTTIMEOUT (default 30 minutes)
> soft session limits in minutes; session will be removed if there is no activity within this time.
- HARDTIMEOUT (default 480 minutes , i.e. 8 hours)
> hard session limits in minutes; session will be removed aftfer this time regardless of activity.
- PWRESETTIMEOUT (default 60 minutes)
> a password reset request must be confirmed within this time.
- REGISTERTIMEOUT (default 60 minutes)
> a registration request must be confirmed within this time.

## Email templates
Confirmation emails are sent when someone registers a new account or has forgotten their password.
Authserver comes bundled with two very basic templates but you can either change these templates or point to different ones:

- EMAILTEMPLATE_FORGOTPASSWORD (default `mailtemplates/passwordreset.mail`)
> send when someone requests a password reset.
- EMAILTEMPLATE_REGISTER (default `mailtemplates/registration.mail`)
> send when a new user wants to register.

## Example docker-compose.yml
Authserver is one component in a larger solution that consists of several services. The relevant service definition from the docker-compose.yml looks like this:

```yaml
    authserver:
    image: authserver
    networks:
      - appnetwork
    environment: # if environment variables are set they override the files; set DEBUGLEVEL to INFO for production
      - SMTP_SERVER
      - SMTP_USER
      - SMTP_PASSWORD
      - ADMIN_USER
      - ADMIN_PASSWORD
      - DOMAIN
      - APPLICATION
      - LOGINSCREEN
      - CONFIRMREGISTRATION
      - RESETPASSWORD
      - SMTP_SERVER_FILE=/run/secrets/smtp-server
      - SMTP_USER_FILE=/run/secrets/smtp-user
      - SMTP_PASSWORD_FILE=/run/secrets/smtp-password
      - ADMIN_USER_FILE=/run/secrets/admin-user
      - ADMIN_PASSWORD_FILE=/run/secrets/admin-password
      - DATABASE_FILE=/var/lib/sqlite/user.db
      - DATABASE_BACKOFF=1
      - DATABASE_RETRIES=3
    env_file: .env
    secrets:
      - smtp-server
      - smtp-user
      - smtp-password
      - admin-user
      - admin-password
    volumes:
      - "userdata:/var/lib/sqlite"
    restart: on-failure
    build:
      context: .
      dockerfile: authserver/Dockerfile
```

The way this is set up we can store sensitive config info in secrets (i.e. files on the server) while the rest of the environment variables might be defined in an `.env` file or even overridden with an explicitely set environment variable.

Also note that the full `docker-compose.yml` file we use in the dockerplayground project has a `labels` section that defines the configuration of the reverse proxy (traefik) to strip `..../auth/....` from any incoming urls and redirect those to Authserver. That way Authserver can run inside its own container will the other parts of the solution might run on their own container(s).

# Usage
Authserver is designed to be application agnostic: It should be able to function as the authentication back-end for any front-end application.

It is up to the front-end application to present the user with forms to login or logout, as well as provide a registration screen and an option to request a password reset if the end user has forgotten it.

Authserver provides *endpoints* that can be used as the URL used in the action of a `<form>` element. Those are [listed below](#available-endpoints).

## Solution Design

![Overview of position of authserver in general solution](https://raw.githubusercontent.com/varkenvarken/dockerplayground/master/authserver/docs/Authserver%20in%20general%20solution.svg)

## Available endpoints
Authserver acts on a small set of URLs to maintain session state and to provide information

- `/login`
This is the action end of a login form
it accepts a POST verb with the following from encoded parameters in the body
   - email
   - password
   - login
- `/logout`
This is the action end of a logout form
it accepts a POST verb and the body should be empty
a valid sessionid cookie must be provided by the browser.
- `/verifysession`
This should not be accessible from the outside and can be used by your application's backend to verify a session
it accepts a POST verb with the following from encoded parameters in the body
  - sessionid
it returns the email address and superuser status of the user associated with the session.
- `/register`
This is the action end of a registration form
it accepts a POST verb with the following from encoded parameters in the body
   - email
   - name
   - password
   - password2
   - login
- `/confirmregistration`
This is typically clicked by the end user because it was sent in an email
it accepts a GET verb with the following query parameter
   - confirmationid
- `/forgotpassword`
This is the action end of a forgot password form
it accepts a POST verb with the following from encoded parameters in the body
   - email
   - login
- `/confirmforgotpassword`
This is typically clicked by the end user because it was sent in an email
it accepts a GET verb with the following query parameter
   - confirmationid
it will redirect to the login page with `?choosepassword=<id>` attached as query parameter.
- `/choosepassword`
This is the action end of a choose new password form
it accepts a POST verb with the following from encoded parameters in the body
   - email
   - password
   - password2
   - resetid
   - login
`resetid` is identical the the one supplied with the confirmpassword url and should typically be included as a hidden field
and extracted for this purpose by the client application's login.html from the redirection url. For an example see the end of
[login.js](https://github.com/varkenvarken/dockerplayground/blob/master/frontend/www/javascript/login.js) used in the dockerplayground frontend.
- `/stats/{item}`
This endpoint provides an overview of the current data in the database.

`{item}` can be `users`, `sessions`, `pendingusers` and `passwordresets` and data is returned in JSON format.

It accepts a POST verb and the body should be empty but a valid sessionid cookie should be provided for a user who has the superuser role.

#Source Documentation

Source documentation for the authserver package is available [here](https://github.com/varkenvarken/dockerplayground/blob/master/authserver/docs/server.md).
