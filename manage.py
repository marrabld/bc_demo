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
        for i_iter in range(0, 8):
            date = datetime.datetime(year=2017, month=11, day=i_iter + 1, hour=9, minute=30, second=0, tzinfo=None)
            _id = i_iter
            pi = 'Dan Marrable <d.marrable@curtin.edu.au>'
            last_published_date = datetime.datetime.now()
            if i_iter == 14 or i_iter == 5:
                transfer_success = False
            else:
                transfer_success = True

            s = transfer.Schedule(id=_id,
                                  date_time=date,
                                  pi=pi,
                                  last_published_date=last_published_date,
                                  transfer_success=transfer_success)
            db.session.add(s)
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


@manager.command
def start_scheduler():
    """
    Set the scheduler to run regularly.  defaults to  every 3 hours.
    """
    api.db.scheduler.set_schedule()
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    manager.run()