from os import environ
from sys import stderr
import falcon
from loguru import logger
from .server import get_sessionmaker, add_superuser, LoginResource, LogoutResource, VerifySessionResource, RegisterResource, ConfirmRegistrationResource, ForgotPasswordResource, ConfirmForgotPasswordResource, ChoosePasswordResource, StatsResource


logger.remove()
logger.add(stderr, level=environ['DEBUGLEVEL'] if 'DEBUGLEVEL' in environ else 'DEBUG')

app = None

if get_sessionmaker(f"sqlite:///{environ['DATABASE_FILE']}", int(environ['DATABASE_BACKOFF']), int(environ['DATABASE_RETRIES'])):
    if add_superuser():
        app = falcon.API()
        app.req_options.auto_parse_form_urlencoded = True
        app.add_route('/login',                 LoginResource())
        app.add_route('/logout',                LogoutResource())
        app.add_route('/verifysession',         VerifySessionResource())
        app.add_route('/register',              RegisterResource())
        app.add_route('/confirmregistration',   ConfirmRegistrationResource())
        app.add_route('/forgotpassword',        ForgotPasswordResource())
        app.add_route('/confirmforgotpassword', ConfirmForgotPasswordResource())
        app.add_route('/choosepassword',        ChoosePasswordResource())
        app.add_route('/stats/{item}',          StatsResource())
        # TODO add change password functionality
        logger.success('falcon app started')
    else:
        logger.critical("could not start falcon app")
else:
    logger.critical(f"could not start database {environ['DATABASE_FILE']}")
