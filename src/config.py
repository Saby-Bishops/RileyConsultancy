# config.py
import os
import secrets
from dotenv import load_dotenv
import logging
from pathlib import Path
# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Find and load .env file - checking multiple possible locations
env_paths = [
    '.env',  # Current directory
    '../.env',  # Parent directory
    Path(__file__).parent / '.env',  # Same directory as this file
    Path(__file__).parent.parent / '.env',  # Parent of this file's directory
]

loaded = False
for env_path in env_paths:
    if os.path.isfile(env_path):
        logger.info(f"Loading environment variables from: {env_path}")
        load_dotenv(env_path)
        loaded = True
        break

if not loaded:
    logger.warning("No .env file found! Using environment variables as is.")

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

    DEFAULT_SCANNER = os.environ.get('DEFAULT_SCANNER', 'gvm')  # Default scanner type

    TAILNET_CONNECTION_SETTINGS = {
            "host": os.getenv("TAILNET_HOST"),
            "port": os.getenv("TAILNET_PORT"),
            "user": os.getenv("TAILNET_USER"),
            "password": os.getenv("TAILNET_PASS"),
            "db": os.getenv("TAILNET_DB"),
        }