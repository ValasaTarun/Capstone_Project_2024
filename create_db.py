import sqlite3

def create_tables(conn):
    cursor = conn.cursor()
    # Create users table

    cursor.execute('''CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        description TEXT NOT NULL)''')

    # Create users table with a foreign key reference to devices
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        devices TEXT NULL,
                        role TEXT NOT NULL DEFAULT 'GUEST'
                        )''')

def insert_devices(conn):
    cursor = conn.cursor()
    # Insert devices data
    devices = [
        ('Smart Light', 'Control your lights remotely.'),
        ('Smart Fan', 'Control your fan remotely.'),
        ('Front Door Cam', 'Monitor your front door.'),
        ('Patio Cam', 'Monitor your patio.'),
        ('Thermostat', 'Control your home temperature.')
    ]
    cursor.executemany('INSERT INTO devices (name, description) VALUES (?, ?)', devices)

def insert_user(conn, username, password):
    cursor = conn.cursor()
    # Insert user data
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))

def drop_tables(conn):
    cursor = conn.cursor()

    # Drop users table
    cursor.execute('''DROP TABLE IF EXISTS users''')

    # Drop devices table
    cursor.execute('''DROP TABLE IF EXISTS devices''')
    print('-tables dropped')
    conn.commit()

if __name__ == '__main__':
    conn = sqlite3.connect('iot_devices.db')
    drop_tables(conn)
    create_tables(conn)
    insert_devices(conn)
    # insert_user(conn, 'keerthangopu34@gmail.com', 'Password@123456')
    conn.commit()
    conn.close()
    print('Database created successfully.')
