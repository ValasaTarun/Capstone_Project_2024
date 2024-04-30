from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from database import get_devices, authenticate,get_user_by_username,add_user,store_fingerprint
import database
import random
import string
import os
import bcrypt
import usb.core
import usb.util

app = Flask(__name__)
app.secret_key = 'your_secret_key'


template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app.template_folder = template_dir


app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USERNAME'] = 'app-testt@outlook.com'  
app.config['MAIL_PASSWORD'] = 'test@Tar213'  
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)


TO_EMAIL = "keerthangopu34@gmail.com"


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))
    

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_admin(username, password):
            session['role'] = 'admin'
            otp = generate_otp()
            session['otp'] = otp

            return redirect(url_for('verify_otp'))
        
        if authenticate(username, password):
            
            otp = generate_otp()
            session['otp'] = otp
            session['username'] = username


            return redirect(url_for('verify_otp'))
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html')

def authenticate_admin(username, password):
    user = get_user_by_username(username)
    
    if user is None:
        return False  
    
    
    if user[4] == 'ADMIN' and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return True
    
    return False

@app.route('/biometric', methods=['GET', 'POST'])
def biometric():
    devices = usb.core.find(find_all=True)
    for device in devices:
    
        if device.port_number == 1 and device.port_numbers[0] == 1:

            if device.is_kernel_driver_active(0):
                device.detach_kernel_driver(0)

            device.set_configuration()

            endpoint_in = device[0][(0, 0)][0]
            endpoint_out = device[0][(0, 0)][1]

            data_to_send = b'\x01\x02\x03\x04'  
            endpoint_out.write(data_to_send)

            user_id = request.form['user_id']
            data_received = device.read(endpoint_in.bEndpointAddress, endpoint_in.wMaxPacketSize)

            store_fingerprint(data_received,user_id)
            
            usb.util.dispose_resources(device)
    return render_template('biometric.html')



@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_entered = request.form['otp']
        if otp_entered == session['otp']:
            
            session['logged_in'] = True
            return redirect(url_for('biometric'))
        else:
            return render_template('verify_otp.html', message='Invalid OTP')
    
    return render_template('verify_otp.html')



@app.route('/home')
def home():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    user = get_user_by_username(session['username'])

    devices = database.get_devices_for_user(0,user)
    print(devices,'from db file')
    user_devices = []
    devices_list = []
    if len(devices[1]) != 0:
        devices_list = list(map(int,devices[1].split(',')))
    for device in devices[0]:
        if device[0] in devices_list:
            user_devices.append(device)
    return render_template('home.html', devices=user_devices)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        
        if not add_user(username, hashed_password):
            message = "Username is already taken. Please try another one."
            return render_template('register.html', message=message)
        
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()  
    return redirect(url_for('login'))  


@app.route('/users')
def view_users():
    users = database.get_all_users()
    return render_template('users.html', users=users)


@app.route('/devices')
def view_devices():
    devices = database.get_all_devices()
    return render_template('devices.html', devices=devices)


@app.route('/admin')
def admin():
    if 'role' not in session or 'admin' not in session['role']:
        return 'You do not have permission to access this page.', 403
    devices = database.get_all_devices()
    
    users = database.get_all_users()
    index = 1
    users_dict = {}
    for user in users:
        users_dict[index] = user
        index += 1
    
    return render_template('admin.html', users=users_dict,devices = devices)



@app.route('/admin/delete_device', methods=['POST'])
def delete_device():
    devices = database.get_all_devices()    
    if request.method == 'POST':
        device_id = request.form['device_id']
        database.delete_device(device_id)
    return redirect(url_for('admin'))


@app.route('/admin/add_device_admin', methods=['POST'])
def add_device_admin():
    devices = database.get_all_devices()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        database.add_device(name, description)
    return redirect(url_for('admin'))
    

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if request.method == 'POST':
        user_id = request.form['user_id']
        database.delete_user(user_id)
    return redirect(url_for('admin'))


@app.route('/admin/update_role', methods=['POST'])
def update_role():
    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['role']
        database.update_user_role(user_id, new_role)
    return redirect(url_for('admin'))


@app.route('/add_device/<int:user_id>/<int:device_id>')
def add_device(user_id,device_id):
    
    
    
    

    
    database.add_device_to_user(user_id, device_id)
    return redirect(url_for('assignment', userid=user_id))


@app.route('/remove_device/<int:user_id>/<int:device_id>',methods=['GET'])
def remove_device(user_id,device_id):
    
    
    
    

    
    database.remove_device_from_user(user_id, device_id)
    return redirect(url_for('assignment', userid=user_id))


@app.route('/assignment/<int:userid>',methods=['GET'])
def assignment(userid):
    
    user_name = database.get_user_name(userid)
    devices = database.get_devices_for_user(userid)
    print('------------------')
    
    return render_template('assignment.html', user_name=[user_name,userid], devices=devices[0],user_devices =  list(map(int,devices[1].split(','))) if len(devices[1]) != 0 else [])


def send_otp_email(username, otp):
    msg = Message('Your OTP for Two-Factor Authentication', sender='app-testt@outlook.com', recipients=[username, TO_EMAIL])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
