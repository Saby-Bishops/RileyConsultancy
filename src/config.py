# config.py
import os
import secrets

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(24)
    DEBUG = os.environ.get('FLASK_DEBUG', 'True') == 'True'
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    ALLOWED_EXTENSIONS = {'csv'}
    
    # Database settings
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), os.pardir, 'db', 'shopsmart.db')

    AUTO_START_NIDS = os.environ.get('AUTO_START_NIDS', 'False') == 'True'

    INTERFACE_NAME = "eth0"
    NIDS_INTERFACE = os.environ.get('NIDS_INTERFACE', INTERFACE_NAME)