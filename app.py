from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from database import get_devices, authenticate,get_user_by_username,add_user
import database
import random
import string
import os
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Specify the path to the templates folder
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app.template_folder = template_dir

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'  # Your SMTP server
app.config['MAIL_PORT'] = 587  # Your SMTP port
app.config['MAIL_USERNAME'] = 'app-testt@outlook.com'  # Your email username
app.config['MAIL_PASSWORD'] = 'test@Tar213'  # Your email password
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)

# Additional recipient email
TO_EMAIL = "keerthangopu34@gmail.com"

# Function to generate OTP
def generate_otp():
    # return ''.join(random.choices(string.digits, k=6))
    return '1234'

# Route for login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_admin(username, password):
            session['role'] = 'admin'
            otp = generate_otp()
            session['otp'] = otp
            # return redirect(url_for('admin'))
            return redirect(url_for('verify_otp'))
        
        if authenticate(username, password):
            # Generate and store OTP in session
            otp = generate_otp()
            session['otp'] = otp
            session['username'] = username

            # Send OTP to user's email
            # send_otp_email(username, otp)
            # Redirect to OTP verification page
            return redirect(url_for('verify_otp'))
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html')

def authenticate_admin(username, password):
    user = get_user_by_username(username)
    # print(user ,bcrypt.checkpw(password.encode('utf-8'), user[2]) )
    if user is None:
        return False  # User not found
    
    # Check if the user is an admin
    if user[4] == 'ADMIN' and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return True
    
    return False

@app.route('/biometric', methods=['GET', 'POST'])
def biometric():
    return render_template('biometric.html')


# # Route for OTP verification page
# @app.route('/verify-otp', methods=['GET', 'POST'])
# def verify_otp():
#     if 'otp' not in session:
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         otp_entered = request.form['otp']
#         if otp_entered == session['otp']:
#             # OTP verification successful, proceed to home page
#             session['logged_in'] = True
#             if session.get('role') == 'admin':
#                 return redirect(url_for('admin'))  # Redirect admin to admin page
#             else:
#                 return redirect(url_for('home'))
#         else:
#             return render_template('verify_otp.html', message='Invalid OTP')
#     return render_template('verify_otp.html')

# Route for OTP verification page
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_entered = request.form['otp']
        if otp_entered == session['otp']:
            # OTP verification successful, proceed to biometric page
            session['logged_in'] = True
            return redirect(url_for('biometric'))
        else:
            return render_template('verify_otp.html', message='Invalid OTP')
    
    return render_template('verify_otp.html')


# Route for home page
@app.route('/home')
def home():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    user = get_user_by_username(session['username'])
    # print(session['username'])
    # devices = get_devices()
    # print(devices,'get_all\n')
    # print(database.get_devices_for_user(0,user)[1],'for user')
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

# Route for registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Check if the username is already taken
        if not add_user(username, hashed_password):
            message = "Username is already taken. Please try another one."
            return render_template('register.html', message=message)
        
        # User added successfully, redirect to login page
        return redirect(url_for('login'))
    
    # GET request: render the registration form
    return render_template('register.html')

# Route for logout
@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page after logout

# Route to view information of the 'users' table
@app.route('/users')
def view_users():
    users = database.get_all_users()
    return render_template('users.html', users=users)

# Route to view information of the 'devices' table
@app.route('/devices')
def view_devices():
    devices = database.get_all_devices()
    return render_template('devices.html', devices=devices)

# Route to display admin users
@app.route('/admin')
def admin():
    if 'role' not in session or 'admin' not in session['role']:
        return 'You do not have permission to access this page.', 403
    devices = database.get_all_devices()
    # print(devices)
    users = database.get_all_users()
    index = 1
    users_dict = {}
    for user in users:
        users_dict[index] = user
        index += 1
    # print(users_dict)
    return render_template('admin.html', users=users_dict,devices = devices)


# Route to delete a device
@app.route('/admin/delete_device', methods=['POST'])
def delete_device():
    devices = database.get_all_devices()    
    if request.method == 'POST':
        device_id = request.form['device_id']
        database.delete_device(device_id)
    return redirect(url_for('admin'))

# Route to add a device
@app.route('/admin/add_device_admin', methods=['POST'])
def add_device_admin():
    devices = database.get_all_devices()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        database.add_device(name, description)
    return redirect(url_for('admin'))
    
# Route to delete a user
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if request.method == 'POST':
        user_id = request.form['user_id']
        database.delete_user(user_id)
    return redirect(url_for('admin'))

# Route to update user's role
@app.route('/admin/update_role', methods=['POST'])
def update_role():
    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['role']
        database.update_user_role(user_id, new_role)
    return redirect(url_for('admin'))

# Route to add a device for a user
@app.route('/add_device/<int:user_id>/<int:device_id>')
def add_device(user_id,device_id):
    # Get user ID from session or any other method
    # user_id = session.get('user_id')
    # if user_id is None:
    #     return redirect(url_for('login'))  # Redirect to login if user is not logged in

    # Add the device to the user's devices list in the database
    database.add_device_to_user(user_id, device_id)
    return redirect(url_for('assignment', userid=user_id))

# Route to remove a device for a user
@app.route('/remove_device/<int:user_id>/<int:device_id>',methods=['GET'])
def remove_device(user_id,device_id):
    # Get user ID from session or any other method
    # user_id = session.get('user_id')
    # if user_id is None:
    #     return redirect(url_for('login'))  # Redirect to login if user is not logged in

    # Remove the device from the user's devices list in the database
    database.remove_device_from_user(user_id, device_id)
    return redirect(url_for('assignment', userid=user_id))

# Route to display assignment for a user
@app.route('/assignment/<int:userid>',methods=['GET'])
def assignment(userid):
    # Fetch user's name and list of devices
    user_name = database.get_user_name(userid)
    devices = database.get_devices_for_user(userid)
    print('------------------')
    # print(devices[0][0],list(map(int,devices[1].split(','))))
    return render_template('assignment.html', user_name=[user_name,userid], devices=devices[0],user_devices =  list(map(int,devices[1].split(','))) if len(devices[1]) != 0 else [])

# Helper function to send OTP email
def send_otp_email(username, otp):
    msg = Message('Your OTP for Two-Factor Authentication', sender='app-testt@outlook.com', recipients=[username, TO_EMAIL])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
