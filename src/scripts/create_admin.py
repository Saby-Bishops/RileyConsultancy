import os
import sys
from werkzeug.security import generate_password_hash
import sqlite3

def create_admin_user(db_path, username, password, email=None):
    """Create an admin user in the database"""
    # Connect to the database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        print(f"User '{username}' already exists!")
        conn.close()
        return False
    
    # Create user
    password_hash = generate_password_hash(password)
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
            (username, password_hash, email, 'admin')
        )
        conn.commit()
        print(f"Admin user '{username}' created successfully!")
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating admin user: {str(e)}")
        conn.close()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <username> <password> [email]")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    email = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Get database path from environment or use default
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, os.pardir, os.pardir))
    default_path = os.path.join(project_root, 'db', 'shopsmart.db')
    db_path = os.environ.get('DATABASE_PATH', default_path)
    
    create_admin_user(db_path, username, password, email)