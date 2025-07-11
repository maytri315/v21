import sqlite3

conn = sqlite3.connect('C:/vehicle_parking_app/instance/parking.db')
cursor = conn.cursor()
for table in ['parking_lot', 'parking_spot', 'user', 'reservation']:
    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'")
    schema = cursor.fetchone()
    print(f"\nSchema for {table}:")
    print(schema[0] if schema else "Table not found")
conn.close()