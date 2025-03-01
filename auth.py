# auth.py
import mysql.connector
from config import DB_CONFIG
import bcrypt

# auth.py (updated)
class User:
    @staticmethod
    def authenticate(username, password):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user:
                stored_hash = user[2]  # Get the stored hash from the database
                print(f"[DEBUG] Stored hash: {stored_hash}")  # Debug line to see the hash
                
                # Check if the hash is a valid bcrypt hash
                if not stored_hash.startswith("$2b$"):
                    print("[ERROR] Stored hash is not a bcrypt hash!")
                    return None
                
                # Verify the password
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    return User(user[0], user[1], user[3])
                else:
                    print("[ERROR] Password verification failed")
            return None
        except Exception as e:
            print(f"[ERROR] Authentication failed: {e}")
            return None
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    @staticmethod
    def register(username, password):
        """
        Registers a new user with a hashed password.
        """
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            # Hash the password and decode it to a UTF-8 string
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            conn.commit()
            return True
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return False
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

class Activity:
    @staticmethod
    def log(user_id, action, log_type):
        """
        Logs an activity performed by a user.
        """
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO activities (user_id, action, log_type) VALUES (%s, %s, %s)",
                           (user_id, action, log_type))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()