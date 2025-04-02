import os
from functools import wraps
from flask import Flask, flash, redirect, render_template, request, session, url_for, abort
import mysql.connector
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
# Generate a secure random key to create sessions
app.secret_key = secrets.token_hex(16)

# Setup the serializer for generating Password reset token
s = URLSafeTimedSerializer(app.secret_key)

# Mail configuration for password reset
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # use environment variables
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # use environment variables

mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# Database Connection
def create_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="",  # Update with actual DB username
            password="",  # Update with actual DB password
            database=""  # Update with actual database name
        )
        if connection.is_connected():
            print("Connected to MySQL DB")  # Print message if the connection is successful
            return connection
        else:
            print("Database connection failed")
            return None
    except mysql.connector.Error as e:
        print(f'Error connecting to MySQL DB: {e}')
        return None

# Role-based decorator
def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Validating user in DB 
def verify_user(email, password):
    try:
        connection = create_db_connection()
        if not connection:
            flash('DB connection error', 'error')
            return None

        cursor = connection.cursor(dictionary=True)

        # Check the `users` table
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        # Compare plain text passwords (for testing purposes only)
        if user and user['password'] == password:
            return user  # Return user if found in `users` table

        return None
    except mysql.connector.Error as e:
        print(f"Error verifying user: {e}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


# Initialize OAuth
oauth = OAuth(app)

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = 'your-google-client-id.apps.googleusercontent.com'  # Replace with your Google client ID
app.config['GOOGLE_CLIENT_SECRET'] = 'your-google-client-secret'  # Replace with your Google client secret
app.config['SECRET_KEY'] = ''  # set securely

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v1/userinfo',  # This is the endpoint for user info
    client_kwargs={'scope': 'openid email profile'},
)

# Google Login Route
@app.route('/google-login')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google-authorize')
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()

    # Check if the user exists in the database
    email = user_info['email']
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            if request.referrer:
                return redirect(request.referrer)  # Redirect back to the previous page
            else:
                return redirect(url_for('tenant_login'))  # Fallback to tenant login if referrer is not available

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # Log the user in
            login_user(User(user['id'], user['email'], user['role']))
            flash('Login Successful!', 'success')

            # Redirect based on user role
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'landlord':
                return redirect(url_for('landlord_dashboard'))
            else:
                return redirect(url_for('tenant_dashboard'))
        else:
            flash('No account associated with this Google account.', 'error')
            return redirect(url_for('tenant_login'))  # Default to tenant login
    except mysql.connector.Error as e:
        flash(f"Error checking user: {e}", "error")
        return redirect(url_for('tenant_login'))  # Default to tenant login
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# User model for Flask-Login (with role)
class User(UserMixin):
    def __init__(self, id, email, role):
        self.id = id
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        connection.close()
        if user:
            return User(user['id'], user['email'], user['role'])
    return None

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

# Admin login
@app.route('/', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        print(f"Login attempt with email: {email}")

        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('admin_login'))

        admin = verify_user(email, password)
        if admin:
            print(f"User found: {admin}")
        else:
            print("User not found or invalid password")

        if admin and admin['role'] == 'admin':
            login_user(User(admin['id'], admin['email'], admin['role']))
            flash('Login Successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login_error.html')
    
    return render_template('login_admin.html')

# Admin dashboard
@app.route('/admin-dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_login'))

        cursor = connection.cursor(dictionary=True)

        # Fetch total landlords
        cursor.execute("SELECT COUNT(*) AS total_landlords FROM users WHERE role='landlord'")
        total_landlords = cursor.fetchone()['total_landlords']

        # Fetch landlords
        cursor.execute("SELECT * FROM users WHERE role='landlord'")
        landlords = cursor.fetchall()

        # Fetch total tenants
        cursor.execute("SELECT COUNT(*) AS total_tenants FROM tenants ")
        total_tenants = cursor.fetchone()['total_tenants']

        # Fetch tenants
        cursor.execute("SELECT * FROM tenants")
        tenant = cursor.fetchall()

        return render_template('admin_dashboard.html', landlords=landlords, tenant=tenant, total_tenants=total_tenants, total_landlords=total_landlords,)
    
    except mysql.connector.Error as e:
        flash(f"Error loading admin dashboard: {e}", 'error')
        return redirect(url_for('admin_login'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/search_landlord', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def search_landlord():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        try:
            connection = create_db_connection()
            cursor = connection.cursor(dictionary=True)
            query = "SELECT * FROM users WHERE role='landlord' AND (first_name LIKE %s OR last_name LIKE %s)"
            cursor.execute(query, (f'%{search_query}%', f'%{search_query}%'))
            landlords = cursor.fetchall()
            return render_template('admin_dashboard.html', landlords=landlords)
        except mysql.connector.Error as e:
            flash(f"Error searching landlords: {e}", "error")
            return redirect(url_for('admin_dashboard'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()
    return render_template('admin_dashboard.html')

# Add Landlord Function
@app.route('/add_landlord', methods=['GET', 'POST'])
@login_required
@role_required('admin')  # Only admins can add landlords
def add_landlord():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        # Validate the input
        if not first_name or not last_name or not email or not phone or not password:
            flash("All fields are required!", "error")
            return redirect(url_for('add_landlord'))

        # Generate unique landlord ID
        landlord_id = generate_unique_landlord_id()

        # Hash the password for security
        password = generate_password_hash('defaultpassword')  # Default password can be changed

        # Insert landlord into the database
        try:
            connection = create_db_connection()
            if not connection:
                flash("Database connection error", 'error')
                return redirect(url_for('add_landlord'))

            cursor = connection.cursor(dictionary=True)
            query = """ 
                INSERT INTO users (landlord_id, first_name, last_name, email, phone, password, role)
                VALUES (%s, %s, %s, %s, %s, %s, 'landlord')
            """
            cursor.execute(query, (landlord_id, first_name, last_name, email, phone, password))
            connection.commit()

            flash('Landlord added successfully!', 'success')

            return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard
        
        except mysql.connector.Error as e:
            flash(f"Error adding landlord: {e}", "error")
            return redirect(url_for('add_landlord'))
        
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

    return url_for('admin_dashboard')

# Function to generate unique landlord ID
def generate_unique_landlord_id():
    connection = create_db_connection()
    if not connection:
        flash("Database connection error", 'error')
        return None

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT landlord_id FROM users WHERE role='landlord' ORDER BY landlord_id DESC LIMIT 1")
    last_landlord = cursor.fetchone()

    if last_landlord:
        last_id = last_landlord['landlord_id']
        number_part = int(last_id[3:])  # Extract the numeric part after 'lan'
        new_number = number_part + 1
    else:
        new_number = 1  # If no landlords exist, start from 1

    landlord_id = f"lan{new_number:03}"  # Format with leading zeros (e.g., lan001, lan002, etc.)
    return landlord_id

# View all landlords
@app.route('/view-landlords')
@login_required
@role_required('admin')
def view_landlords():
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = connection.cursor(dictionary=True)

        # Fetch landlords
        query_landlords = "SELECT * FROM users WHERE role='landlord'"
        cursor.execute(query_landlords)
        landlords = cursor.fetchall()

        return render_template('landlords.html', landlords=landlords)
    except mysql.connector.Error as e:
        flash(f"Error loading landlords: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Add Tenant Function
@app.route('/add_tenant', methods=['GET', 'POST'])
@login_required
@role_required('admin')
@role_required('landlord')  # Only admins and landlords can add tenants
def add_tenant():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        landlord_id = request.form.get('landlord_id')

        # Validate the input
        if not first_name or not last_name or not email or not phone or not password or not landlord_id:
            flash("All fields are required!", "error")
            return redirect(url_for('add_tenant'))

        # Insert tenant into the centralized tenants table
        try:
            connection = create_db_connection()
            if not connection:
                flash("Database connection error", 'error')
                return redirect(url_for('add_tenant'))

            cursor = connection.cursor(dictionary=True)

            # Insert tenant into the tenants table
            query = """
                INSERT INTO tenants (first_name, last_name, email, phone, password, landlord_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (first_name, last_name, email, phone, password, landlord_id))
            connection.commit()

            flash('Tenant added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to admin's dashboard
        
        except mysql.connector.Error as e:
            flash(f"Error adding tenant: {e}", "error")
            return redirect(url_for('add_tenant'))
        
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

    # Fetch landlords for the dropdown
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = connection.cursor(dictionary=True)
        query = "SELECT id, first_name, last_name FROM users WHERE role='landlord'"
        cursor.execute(query)
        landlords = cursor.fetchall()
    except mysql.connector.Error as e:
        flash(f"Error loading landlords: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

    return render_template('add_tenant.html', landlords=landlords)

# Search Tenant Function
@app.route('/search_tenant', methods=['GET', 'POST'])
@login_required
@role_required('admin')
# Only admins and landlords should access this page
def search_tenant():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        # Implement the search logic based on search_query
        try:
            connection = create_db_connection()
            cursor = connection.cursor(dictionary=True)
            query = "SELECT * FROM tenants WHERE (first_name LIKE %s OR last_name LIKE %s)"
            cursor.execute(query, (f'%{search_query}%', f'%{search_query}%'))
            tenants = cursor.fetchall()
            return render_template('dashboard_landlord.html', tenants=tenants)
        except mysql.connector.Error as e:
            flash(f"Error searching tenant: {e}", "error")
            return redirect(url_for('landlord_dashboard'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()
    return render_template('dashboard_landlord.html')

# Admin view all tenants
@app.route('/tenants')
@login_required
@role_required('admin')
def tenants():
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = connection.cursor(dictionary=True)

        # Fetch tenants along with their associated landlords
        query = """
            SELECT 
                tenants.id AS tenant_id,
                tenants.first_name AS tenant_first_name,
                tenants.last_name AS tenant_last_name,
                tenants.email AS tenant_email,
                tenants.phone AS tenant_phone,
                users.id AS landlord_id,
                users.first_name AS landlord_first_name,
                users.last_name AS landlord_last_name,
                users.email AS landlord_email
            FROM tenants
            JOIN users ON tenants.landlord_id = users.id
            WHERE users.role = 'landlord'
        """
        cursor.execute(query)
        tenants_with_landlords = cursor.fetchall()

        return render_template('tenants.html', tenants=tenants_with_landlords)
    except mysql.connector.Error as e:
        flash(f"Error loading tenants: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Landlord login
@app.route('/landlord-login', methods=['GET', 'POST'])
def landlord_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('landlord_login'))

        try:
            # Verify user credentials
            landlord = verify_user(email, password)
            if landlord and landlord['role'] == 'landlord':
                # Log the user in
                login_user(User(landlord['id'], landlord['email'], landlord['role']))
                flash('Login Successful!', 'success')
                return redirect(url_for('landlord_dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return redirect(url_for('landlord_login'))
        except Exception as e:
            flash(f"An error occurred during login: {e}", 'error')
            return redirect(url_for('landlord_login'))

    return render_template('login_landlord.html')

# Landlord dashboard
@app.route('/landlord-dashboard')
@login_required
@role_required('landlord')  # Only landlords should access this page
def landlord_dashboard():
    landlord_id = current_user.id  # Get the ID of the logged-in landlord
    try:
        # Establish database connection
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            return redirect(url_for('landlord_login'))

        cursor = connection.cursor(dictionary=True)

        # Fetch landlord information
        cursor.execute("SELECT * FROM users WHERE id = %s AND role = 'landlord'", (landlord_id,))
        landlord = cursor.fetchone()
        if not landlord:
            flash("Landlord not found", "error")
            return redirect(url_for('landlord_login'))

        # Fetch tenants associated with the landlord
        query = """
            SELECT 
                id AS tenant_id,
                first_name,
                last_name,
                email,
                phone
            FROM tenants
            WHERE landlord_id = %s
        """
        cursor.execute(query, (landlord_id,))
        tenants = cursor.fetchall()

        # Render the landlord dashboard with landlord and tenant data
        return render_template('dashboard_landlord.html', landlord=landlord, tenants=tenants)
    except mysql.connector.Error as e:
        flash(f"Error loading landlord dashboard: {e}", "error")
        return redirect(url_for('landlord_login'))
    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Staff login
@app.route('/staff-login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('staff_login'))

        staff = verify_user(email, password)
        if staff and staff['role'] == 'staff':
            login_user(User(staff['id'], staff['email'], staff['role']))
            flash('Login Successful!', 'success')
            return redirect(url_for('staff_input'))  # Redirect to the staff input page
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('staff_login'))

    return render_template('stafflogin.html')

# Staff input page
@app.route('/staff-input') 
@login_required            # Login is required inorder to access this page 
@role_required('staff')  # This ensure only staff can access this page
def staff_input():
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('staff_login'))

        cursor = connection.cursor(dictionary=True)

        # Fetch tenants for the dropdown
        query = "SELECT id, CONCAT(first_name, ' ', last_name) AS name, code FROM tenants"
        cursor.execute(query)
        tenants = cursor.fetchall()

        return render_template('staff.html', tenants=tenants)
    except mysql.connector.Error as e:
        flash(f"Error loading staff input page: {e}", 'error')
        return redirect(url_for('staff_login'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Tenant login
@app.route('/tenant-login', methods=['GET', 'POST'])
def tenant_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('tenant_login'))

        tenant = verify_user(email, password)
        if tenant and tenant['role'] == 'tenant':
            session['user_id'] = tenant['id']
            login_user(User(tenant['id'], tenant['email'], tenant['role']))
            flash('Login Successful!', 'success')
            return redirect(url_for('tenant_dashboard'))
        else:
            return render_template('tenant_login_error.html')
    
    return render_template('login_tenant.html')

# Tenant dashboard
@app.route('/tenant-dashboard', methods=['GET', 'POST'])
@login_required
@role_required('tenant')
def tenant_dashboard():
    tenant_id = current_user.id  # Get the ID of the logged-in tenant
    try:
        # Establish database connection
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            return redirect(url_for('tenant_dashboard'))

        cursor = connection.cursor(dictionary=True)

        # Query to get tenant information
        cursor.execute("SELECT * FROM users WHERE id = %s AND role = 'tenant'", (tenant_id))
        tenant = cursor.fetchone()
        if not tenant:
            flash("Tenant not found", "error")
            return redirect(url_for('tenant_login'))

        # Query to get tenant-specific data (e.g., waste management data)
        # Replace 'tenant_data_table' with the actual table name
        cursor.execute(f"SELECT * FROM tenant_data_table WHERE tenant_id = %s", (tenant_id))
        tenant_data = cursor.fetchall()

        return render_template('dashboard_tenant.html', tenant=tenant, tenant_data=tenant_data)
    except mysql.connector.Error as e:
        flash(f"Error loading tenant dashboard: {e}", "error")
        return redirect(url_for('tenant_login'))
    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Edit tenant information                 
@app.route('/edit_tenant/<string:tenant_id>', methods=['GET', 'POST'])
@login_required
@role_required('landlord')
def edit_tenant(tenant_id):
    landlord_id = current_user.id  # Get the ID of the logged-in landlord
    tenant_table_name = f"landlord_{landlord_id}_tenants"

    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('landlord_dashboard'))

        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            phone = request.form.get('phone')

            # Validate the input
            if not first_name or not last_name or not email or not phone:
                flash("All fields are required!", "error")
                return redirect(url_for('edit_tenant', tenant_id=tenant_id))

            # Update tenant information in the landlord-specific tenant table
            query = f"""
                UPDATE {tenant_table_name}
                SET first_name = %s, last_name = %s, email = %s, phone = %s
                WHERE tenant_id = %s
            """
            cursor.execute(query, (first_name, last_name, email, phone, tenant_id))
            connection.commit()

            flash('Tenant information updated successfully!', 'success')
            return redirect(url_for('landlord_dashboard')) # Redirect to landlord's dashboard

        # Fetch tenant information for the form
        query = f"SELECT * FROM {tenant_table_name} WHERE tenant_id = %s"
        cursor.execute(query, (tenant_id,))
        tenant = cursor.fetchone()

        if not tenant:
            flash("Tenant not found", "error")
            return redirect(url_for('landlord_dashboard'))

        return render_template('edit_tenant.html', tenant=tenant)

    except mysql.connector.Error as e:
        flash(f"Error editing tenant: {e}", 'error')
        return redirect(url_for('landlord_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Delete tenant data from tenant_data_table (for landlords)
@app.route('/delete_tenant_data/<int:tenant_id>', methods=['POST'])
@login_required
@role_required('landlord')
def delete_tenant_data(tenant_id):
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('landlord_dashboard'))

        cursor = connection.cursor()
        query = "DELETE FROM tenant_data_table WHERE tenant_id = %s"
        cursor.execute(query, (tenant_id,))
        connection.commit()

        flash('Tenant data deleted successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))
    except mysql.connector.Error as e:
        flash(f"Error deleting tenant data: {e}", 'error')
        return redirect(url_for('landlord_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Delete tenant from landlord-specific tenant table
@app.route('/delete_tenant/<string:tenant_id>', methods=['POST'])
@login_required
@role_required('landlord')
def delete_tenant(tenant_id):
    landlord_id = current_user.id  # Get the ID of the logged-in landlord
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('landlord_dashboard'))

        cursor = connection.cursor()
        tenant_table_name = f"landlord_{landlord_id}_tenants"
        query = f"DELETE FROM {tenant_table_name} WHERE tenant_id = %s"
        cursor.execute(query, (tenant_id,))
        connection.commit()

        flash('Tenant deleted successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))
    except mysql.connector.Error as e:
        flash(f"Error deleting tenant: {e}", 'error')
        return redirect(url_for('landlord_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Delete landlord and associated tenant table as admin
@app.route('/delete_landlord/<int:landlord_id>', methods=['POST'])
@login_required
@role_required('admin')  # Only admins can delete landlords
def delete_landlord(landlord_id):
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = connection.cursor()

        # Delete the landlord from the users table
        delete_landlord_query = "DELETE FROM users WHERE id = %s AND role = 'landlord'"
        cursor.execute(delete_landlord_query, (landlord_id,))
        
        # Drop the landlord-specific tenant table
        tenant_table_name = f"landlord_{landlord_id}_tenants"
        drop_table_query = f"DROP TABLE IF EXISTS {tenant_table_name}"
        cursor.execute(drop_table_query)
        connection.commit()

        flash('Landlord and associated tenant table deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    except mysql.connector.Error as e:
        flash(f"Error deleting landlord: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Password reset request
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = verify_user(email, 'defaultpassword')
        if user:
            token = s.dumps(email, salt='recover-password')
            msg = Message('Password Reset Request', recipients=[email])
            reset_link = url_for('reset_with_token', token=token, _external=True)
            msg.body = f"Click the link below to reset your password:\n{reset_link}"
            mail.send(msg)
            flash('Password reset link sent to your email', 'success')
            return redirect(url_for('tenant_login'))
        else:
            flash('Invalid email address', 'error')
            return redirect(url_for('reset_password'))
    return render_template('reset_password.html')

# Reset password with token
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='recover-password', max_age=3600)
    except:
        flash('The password reset link is invalid or expired', 'error')
        return redirect(url_for('reset_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_with_token', token=token))

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        try:
            connection = create_db_connection()
            if not connection:
                flash("Database connection error", 'error')
                return redirect(url_for('reset_with_token', token=token))

            cursor = connection.cursor()
            query = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(query, (hashed_password, email))
            connection.commit()

            flash('Password reset successful', 'success')
            return redirect(url_for('tenant_login'))
        except mysql.connector.Error as e:
            flash(f"Error resetting password: {e}", 'error')
            return redirect(url_for('reset_with_token', token=token))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

    return render_template('reset_with_token.html')

# Admin Resetting passwords for any user
@app.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def settings():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not user_id or not new_password or not confirm_password:
            flash('Please provide all required fields', 'error')
            return redirect(url_for('settings'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('settings'))

        hashed_password = generate_password_hash(new_password)
        try:
            connection = create_db_connection()
            if not connection:
                flash("Database connection error", 'error')
                return redirect(url_for('settings'))

            cursor = connection.cursor()
            query = "UPDATE users SET password = %s WHERE id = %s"
            cursor.execute(query, (hashed_password, user_id))
            connection.commit()
            flash('Password updated successfully', 'success')
        except mysql.connector.Error as e:
            flash(f"Error updating password: {e}", 'error')
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

        return redirect(url_for('settings'))

    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = connection.cursor(dictionary=True)
        query = "SELECT id, email, role FROM users"
        cursor.execute(query)
        users = cursor.fetchall()
    except mysql.connector.Error as e:
        flash(f"Error loading users: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

    return render_template('settings.html', users=users)

                
# Combined logout function
@app.route('/logout')
def logout():
    logout_user()
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    
    # Redirect based on user role
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_login'))
        elif current_user.role == 'landlord':
            return redirect(url_for('landlord_login'))
        else:
            return redirect(url_for('tenant_login'))
    else:
        return redirect(url_for('admin_login'))


if __name__ == '__main__':
    app.run()