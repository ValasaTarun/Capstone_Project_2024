import sqlite3
import bcrypt

def get_connection():
    return sqlite3.connect('iot_devices.db')

def authenticate(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def get_devices():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM devices')
    devices = cursor.fetchall()
    conn.close()
    return devices

def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def authenticate(username, password):
    user = get_user_by_username(username)
    # print('from authenticate',user,type(user),user[2])
    if user is None:
        return False  # User not found
    # Check if the hashed password matches the provided password
    return bcrypt.checkpw(password.encode('utf-8'), user[2])

def delete_device(device_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM devices WHERE id = ?', (device_id,))
    conn.commit()
    conn.close()

def add_device(name, description):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO devices (name, description) VALUES (?, ?)', (name, description))
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to fetch all users from the 'users' table
def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return users

# Function to fetch all devices from the 'devices' table
def get_all_devices():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM devices')
    devices = cursor.fetchall()
    conn.close()
    return devices

def delete_two_rows():
    conn = get_connection()
    cursor = conn.cursor()

    # Delete the first two rows from the users table
    cursor.execute('''
        DELETE FROM users
        WHERE rowid IN (SELECT id FROM users LIMIT 2)
    ''')

    conn.commit()
    conn.close()

def add_user(username, hashed_password,role='GUEST'):
    conn = get_connection()
    cursor = conn.cursor()
    username_lower = username.lower()
    # Check if the username already exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username_lower,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        conn.close()
        return False  # Username already exists, return False
    
    # Insert user data into the users table
    # cursor.execute('INSERT INTO users (username, password,devices) VALUES (?, ?,?)', (username_lower, hashed_password,''))
    cursor.execute('INSERT INTO users (username, password,devices, role) VALUES (?, ?, ?,?)', (username, hashed_password,'', role))
    conn.commit()
    conn.close()
    return True 

def update_user_role(user_id, new_role):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users')
    users = cursor.fetchall()
    conn.close()    
    return users

def get_user_name(userid):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (userid,))
    user_name = cursor.fetchone()[0]  # Assuming there's only one user with the given ID
    conn.close()
    return user_name

# Function to fetch devices for a user by user ID
def get_devices_for_user(userid,user_name=''):
    conn = get_connection()
    cursor = conn.cursor()
    if user_name == '':
        cursor.execute('SELECT devices FROM users WHERE id = ?', (userid,))
    else:
        cursor.execute('SELECT devices FROM users WHERE username = ?', (user_name[1],))
    user_devices = cursor.fetchall()
    print(user_devices,'from db get_devices_for_user')
    if len(user_devices) != 0:
        print('user_devices = ',user_devices,user_devices[0])
        user_devices = user_devices[0][0]
    # print('from get_all_devies',get_all_devices())
    conn.close()
    return [get_all_devices(),user_devices]

def add_device_to_user(user_id, device_id):
    conn = get_connection()
    cursor = conn.cursor()
    print('user_id = {} , device_id =  {}'.format(user_id,device_id))
    # Get the current devices for the user
    cursor.execute('SELECT devices FROM users WHERE id = ?', (user_id,))
    current_devices = cursor.fetchone()[0]  # Assuming there's only one user with the given ID
    print('current devices',current_devices)
    # Update the devices column with the new device ID
    new_devices = str(current_devices) + ',' + str(device_id) if current_devices else str(device_id)
    print('-adding',new_devices)
    cursor.execute('UPDATE users SET devices = ? WHERE id = ?', (new_devices, user_id))

    conn.commit()
    conn.close()

def remove_device_from_user(user_id, device_id):
    conn = get_connection()
    cursor = conn.cursor()

    # Get the current devices for the user
    cursor.execute('SELECT devices FROM users WHERE id = ?', (user_id,))
    current_devices = cursor.fetchone()[0]  # Assuming there's only one user with the given ID

    # Remove the device ID from the list of current devices
    new_devices = ','.join(filter(lambda x: x != str(device_id), current_devices.split(',')))
    print('-removing',new_devices)

    # Update the devices column with the updated devices list
    cursor.execute('UPDATE users SET devices = ? WHERE id = ?', (new_devices, user_id))

    conn.commit()
    conn.close()

def remove_duplicate_columns():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Identify duplicate columns based on certain criteria
    cursor.execute('''
        DELETE FROM devices
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM devices
            GROUP BY name, description
        )
    ''')
    
    conn.commit()
    conn.close()

# delete_two_rows()