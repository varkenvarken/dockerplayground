# Minimal makefile for Sphinx documentation
#
# exxplicitely set environment variables to show up as default in the docs
export DOMAIN := yourdomain.org
export APPLICATION := /books
export LOGINSCREEN L= /books/login.html
export CONFIRMREGISTRATION := https//server.yourdomain.org/auth/confirmregistration
export RESETPASSWORD := https://server.yourdomain.org/auth/resetpassword
export WEBSITE := "Book Collection"
export SOFTTIMEOUT := 30
export HARDTIMEOUT := 480
export PWRESETTIMEOUT := 60
export REGISTERTIMEOUT := 60
export EMAILTEMPLATE_FORGOTPASSWORD := mailtemplates/passwordreset.mail
export EMAILTEMPLATE_REGISTER := mailtemplates/registration.mail
export ADMIN_USER_FILE := ""
export ADMIN_USER := admin@yourdomain.org
export ADMIN_PASSWORD_FILE := ""
export ADMIN_PASSWORD := "Secre3t!!"
export SMTP_USER := smtpuser@yourdmain.org
export SMTP_SERVER := smtp.local
export SMTP_PASSWORD := "Secre3t!!"

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= /home/michel/.local/bin/sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
