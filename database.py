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
    
    if user is None:
        return False  
    
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


def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return users


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

    cursor.execute('SELECT username FROM users WHERE username = ?', (username_lower,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        conn.close()
        return False 
    
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
    user_name = cursor.fetchone()[0]  
    conn.close()
    return user_name


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
    
    conn.close()
    return [get_all_devices(),user_devices]

def add_device_to_user(user_id, device_id):
    conn = get_connection()
    cursor = conn.cursor()
    print('user_id = {} , device_id =  {}'.format(user_id,device_id))
    
    cursor.execute('SELECT devices FROM users WHERE id = ?', (user_id,))
    current_devices = cursor.fetchone()[0]  
    print('current devices',current_devices)
    
    new_devices = str(current_devices) + ',' + str(device_id) if current_devices else str(device_id)
    print('-adding',new_devices)
    cursor.execute('UPDATE users SET devices = ? WHERE id = ?', (new_devices, user_id))

    conn.commit()
    conn.close()

def remove_device_from_user(user_id, device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT devices FROM users WHERE id = ?', (user_id,))
    current_devices = cursor.fetchone()[0]  

    new_devices = ','.join(filter(lambda x: x != str(device_id), current_devices.split(',')))
    print('-removing',new_devices)

    cursor.execute('UPDATE users SET devices = ? WHERE id = ?', (new_devices, user_id))

    conn.commit()
    conn.close()

def remove_duplicate_columns():
    conn = get_connection()
    cursor = conn.cursor()
    
    
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

