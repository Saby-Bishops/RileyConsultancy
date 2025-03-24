import sys
import os

# Add the path to the 'src' folder to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from app import app  # this works now because 'src' is in sys.path

application = app
