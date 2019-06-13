"""
This is the main entry point of the application
"""
from app import DEBUG, app
import views

if __name__ == '__main__':
    if DEBUG:
        app.logger.error('Staring application in DEBUG mode')
        app.run(debug=True, host='0.0.0.0')
    else:
        app.run()