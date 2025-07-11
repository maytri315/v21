import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/parking.db')
cursor = conn.cursor()

try:
    # Add the created_at column
    cursor.execute("ALTER TABLE parking_lot ADD COLUMN created_at DATETIME")
    # Set default timestamp for existing rows
    cursor.execute("UPDATE parking_lot SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    conn.commit()
    print("Successfully added created_at column to parking_lot table.")
except sqlite3.OperationalError as e:
    print(f"Error: {e}")
    if "duplicate column name" in str(e):
        print("The created_at column already exists.")
finally:
    conn.close()