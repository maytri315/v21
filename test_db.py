import sqlite3

try:
    conn = sqlite3.connect('C:/vehicle_parking_app/instance/parking.db')
    print("Successfully connected to parking.db")
    conn.close()
except sqlite3.OperationalError as e:
    print(f"Error: {e}")