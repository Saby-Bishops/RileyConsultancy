import os
import sys
from werkzeug.security import generate_password_hash

curr_dir = os.path.dirname(os.path.abspath(__file__))
db_man_path = os.path.join(curr_dir, os.pardir)
sys.path.append(db_man_path)

from db_manager import DBManager
from config import Config

db_config = Config()

def create_admin_user(username, password, email=None):
    """Create an admin user in the database"""
    db_manager = DBManager(db_config.TAILNET_CONNECTION_SETTINGS)

    # Connect to the database
    with db_manager.get_cursor() as cursor:
        # Check if user exists
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            print(f"User '{username}' already exists!")
            return False
        
        # Create user
        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)',
                (username, password_hash, email, 'admin')
            )
            print(f"Admin user '{username}' created successfully!")
            return True
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <username> <password> [email]")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    email = sys.argv[3] if len(sys.argv) > 3 else None
    create_admin_user(username, password, email)