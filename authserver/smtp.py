#  smtp.py, a mailer module
#
#  part of https://github.com/varkenvarken/dockerplayground
#
#  (c) 2020 Michel Anders (varkenvarken)
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import os


def mail(message, subject, fromaddr, toaddr, smtp, username, password):
    from smtplib import SMTP_SSL
    with SMTP_SSL(smtp) as smtp:
        smtp.login(username, password)
        smtp.sendmail(fromaddr, toaddr, bytes(f"From: {fromaddr}\r\nTo: {toaddr}\r\nSubject: {subject}\r\n\r\n{message}", 'UTF-8'))


def fetch_smtp_params():
    """
    Get smtp variables from file or environment.

    enviroment variables overrule variables in files.
    """
    env = {}
    for var in ('SMTP_USER', 'SMTP_SERVER', 'SMTP_PASSWORD'):
        if var in os.environ and os.environ[var].strip() != '':
            env[var] = os.environ[var]
        else:
            varf = var + '_FILE'
            if varf in os.environ:
                with open(os.environ[varf]) as f:
                    env[var] = f.read().strip()
            else:
                raise KeyError(f'{var} and {varf} not defined in environment')

    return env['SMTP_USER'], env['SMTP_PASSWORD'], env['SMTP_SERVER']


if __name__ == "__main__":
    u, p, s = fetch_smtp_params()
    mail("test message", "Test", fromaddr=u, toaddr=u, smtp=s, username=u, password=p)
