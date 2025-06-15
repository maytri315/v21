import sqlite3
import os

db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'parking.db')
try:
    conn = sqlite3.connect(db_path)
    print("Connected to database successfully!")
    conn.close()
except sqlite3.OperationalError as e:
    print(f"Error: {e}")