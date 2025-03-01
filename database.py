# database.py
import mysql.connector
from config import DB_CONFIG
import bcrypt  # NEW: Import bcrypt

def init_db():
    """
    Creates the database and required tables if they don't exist.
    Also inserts a default admin user (admin/admin123).
    """
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()

        # Create the database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")

        # Create 'users' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,  # Ensure this is VARCHAR(100)
                role ENUM('admin','user') DEFAULT 'user'
            )
        """)

        # Create 'activities' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(255),
                log_type VARCHAR(50),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # NEW: Hash the default admin password and decode to UTF-8 string
        hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert a default admin user with the hashed password
        cursor.execute("""
            INSERT IGNORE INTO users (username, password, role)
            VALUES (%s, %s, %s)
        """, ('admin', hashed_password, 'admin'))  # Use parameterized query

        conn.commit()
        print("Database initialized successfully!")
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()