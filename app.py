from flask import Flask
from flask_sqlalchemy import SQLAlchemy

import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler

# import configs
try:
    import ConfigParser
except:
    import configparser

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CIC4Life'


# ==============================#
# Logging info
# ==============================#
handler = RotatingFileHandler('./logs/application.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.DEBUG)
handler.setFormatter(Formatter('[%(asctime)s] :: %(levelname)s :: MODULE %(module)s :: lINE %(lineno)d :: %(message)s'))

app.logger.addHandler(handler)

# ==============================#
# Configuration files
# ==============================#
try:
    config = ConfigParser.ConfigParser()
except:
    # import configparser
    config = configparser.ConfigParser()
config.read('server.conf')

environment = config.get('GLOB', 'environment')
app.logger.info('Running in {} mode'.format(environment))

if environment == 'DEV':
    DEBUG = True
else:
    DEBUG = False

# ==============================#
# Set up the data base for recording when we copy and write to the database.
# ==============================#

app.config['SQLALCHEMY_DATABASE_URI'] = config.get(environment, 'database_url')  # !!! Change me on Production

db = SQLAlchemy(app)
