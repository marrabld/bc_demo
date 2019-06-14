#!/usr/bin/python

import datetime
import logging
import os
import pip
import shutil
#import schedule
#import api.db.scheduler
import time

from flask_script import Manager, prompt_bool
from requests import get  # to make GET request

from app import app
from app import config
from app import db
from models import node

app.logger.setLevel(logging.DEBUG)

manager = Manager(app)


@manager.command
def init_db():
    """
    Initialize the database.
    """
    app.logger.info('Initialising the application database')
    db.create_all()
    app.logger.info('Done')


@manager.command
def load_test_data():
    """
    Populate the database with dummy data so we can test the application
    """
    if prompt_bool("Are you sure you want to continue, proceeding will drop all previous data"):
        app.logger.warning('Dropping table before generating dummy data')
        db.drop_all()
        db.create_all()

        app.logger.info("Populating database with dummy data")
        admin = node.User(password='admin', email='admin@example.com')
        guest = node.User(password='guest', email='guest@example.com')
        pwh = None
        db.session.add(admin)
        db.session.add(guest)
        db.session.commit()
        app.logger.info("Done")


@manager.command
def drop_db():
    """
    Drop the database.
    """
    if prompt_bool("Are you sure you want to lose all your data"):
        app.logger.warning('Dropping the database, all data will be lost')
        db.drop_all()
        app.logger.warning('Done')
    else:
        app.logger.info('Skipping')


@manager.command
def clear_cache():
    """
    Delete the directory where the files are cached.
    """
    shutil.rmtree(config.get('DEV', 'cache'), ignore_errors=True)


@manager.command
def run_tests():
    """
    Run the unit tests with nose
    """

    os.system('nose2')
    # import nose2
    # import sys
    # sys.path.append(os.path.realpath('./tests'))
    # nose2.main()
    # #nose2.main(module=tests)
    # #nose2.run(module='./tests', defaultTest='./tests')


if __name__ == "__main__":
    manager.run()