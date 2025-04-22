import os
from functools import wraps
from flask import Flask, flash, redirect, render_template, request, session, url_for, abort
import mysql.connector
import secrets
from itsdangerous import BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from models import User


# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
application = app

# Generate a secure random key to create sessions
app.secret_key = secrets.token_hex(16)

# serializer for generating Password reset token
s = URLSafeTimedSerializer(app.secret_key)

# Mail configuration for password reset
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''  
app.config['MAIL_PASSWORD'] = '' 
app.config['MAIL_DEFAULT_SENDER'] = ''

mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# Database Connection
def create_db_connection():
    try:
        connection = mysql.connector.connect(
            host='',
            user='',
            password='',
            database='',
        )
        if connection.is_connected():
            print("Connected to MySQL DB")
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



# Initialize OAuth
oauth = OAuth(app)

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = ''  
app.config['GOOGLE_CLIENT_SECRET'] = ''
app.config['SECRET_KEY'] = app.secret_key 

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


@app.route('/google-login')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/google-authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()

        user_info = google.get('userinfo').json()

        email = user_info.get('email')

        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            return render_template('nodbconnection.html')

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()


        if user:
            login_user(User(user['id'], user['email'], user['role']))
            flash("Login successful!", "success")

            role = user['role']
            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'landlord':
                return redirect(url_for('landlord_dashboard'))
            else:
                return redirect(url_for('tenant_dashboard'))
        

    except Exception as e:
        flash(f"Login error: {e}", "error")
        return render_template('login_error.html')

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



def verify_user(email, password):
    try:
        connection = create_db_connection()
        if not connection:
            flash('DB connection error', 'error')
            return None

        cursor = connection.cursor(dictionary=True)

        # Check the users table
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        # Use password hash verification
        if user and check_password_hash(user['password'], password):
            return user  # Return user if found and password matches

        return None
    except mysql.connector.Error as e:
        print(f"Error verifying user: {e}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            

# Admin login route 
@app.route('/', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('login_admin.html')

        try:
            # Verify user credentials
            admin = verify_user(email, password)
            if admin and admin['role'] == 'admin':
                # Log the user in
                login_user(User(admin['id'], admin['email'], admin['role']))
                flash('Login Successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return render_template('login_error.html')
        except Exception as e:
            flash(f"An error occurred during login: {e}", 'error')
            return render_template('login_admin.html')

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

        # Fetch total staff
        cursor.execute("SELECT COUNT(*) AS total_staffs FROM users WHERE role = 'staff'")
        total_staffs = cursor.fetchone()['total_staffs']
        
        # Fetch staff
        cursor.execute("SELECT * FROM users WHERE role='staff'")
        staff = cursor.fetchall()
        
        # Fetch total landlords
        cursor.execute("SELECT COUNT(*) AS total_landlords FROM users WHERE role='landlord'")
        total_landlords = cursor.fetchone()['total_landlords']

        # Fetch landlords
        cursor.execute("SELECT * FROM users WHERE role='landlord'")
        landlords = cursor.fetchall()

        # Fetch total tenants
        cursor.execute("SELECT COUNT(*) AS total_tenants FROM users WHERE role='tenant'")
        total_tenants = cursor.fetchone()['total_tenants']

        # Fetch tenants
        cursor.execute("SELECT * FROM users WHERE role='tenant'")
        tenant = cursor.fetchall()

        return render_template('admin_dashboard.html', total_staffs = total_staffs, staff=staff, landlords=landlords, tenant=tenant, total_tenants=total_tenants, total_landlords=total_landlords,)
    
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
        landlord_id = + 1
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
# Only admins and landlords can search for tenants
def search_tenant():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        # Implement the search logic based on search_query
        try:
            connection = create_db_connection()
            cursor = connection.cursor(dictionary=True)
            query = "SELECT * FROM users WHERE (first_name LIKE %s OR last_name LIKE %s)"
            cursor.execute(query, (f'%{search_query}%', f'%{search_query}%'))
            tenants = cursor.fetchall()
            return render_template('admin_dashboard.html', tenants=tenants)
        except mysql.connector.Error as e:
            flash(f"Error searching tenant: {e}", "error")
            return redirect(url_for('admin_dashboard'))
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
                    landlords.id AS landlord_id,
                    landlords.first_name AS landlord_first_name,
                    landlords.last_name AS landlord_last_name,
                    landlords.email AS landlord_email
                    FROM users AS tenants
                    JOIN users AS landlords ON tenants.landlord_id = landlords.id
                    WHERE landlords.role = 'landlord'
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
@app.route('/landlord', methods=['GET', 'POST'])
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
                return render_template('landlord_login_error.html')
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
            FROM users
            WHERE landlord_id = %s
        """
        cursor.execute(query, (landlord_id,))
        tenants = cursor.fetchall()

        # Fetch tenants
        tenants_query = "SELECT id AS tenant_id, first_name, last_name, phone FROM users WHERE landlord_id = %s"
        cursor.execute(tenants_query, (current_user.id,))
        tenants = cursor.fetchall()

        # Fetch total tenants
        total_tenants_query = "SELECT COUNT(*) AS total_tenants FROM users WHERE landlord_id = %s"
        cursor.execute(total_tenants_query, (current_user.id,))
        total_tenants = cursor.fetchone()['total_tenants']


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

@app.route('/landlord/add-tenant', methods=['GET', 'POST'])
@login_required
@role_required('landlord')  # Ensures only landlords can access this route
def landlord_add_tenant():
    landlord_id = current_user.id  # Get the ID of the logged-in landlord

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        # Validate the input
        if not first_name or not last_name or not email or not phone or not password:
            flash("All fields are required!", "error")
            return redirect(url_for('landlord_add_tenant'))

        try:
            connection = create_db_connection()
            if not connection:
                flash("Database connection error", 'error')
                return redirect(url_for('landlord_add_tenant'))

            cursor = connection.cursor(dictionary=True)

            # Insert tenant into the `users` table
            query = """
                INSERT INTO users (first_name, last_name, email, phone, password, landlord_id, role)
                VALUES (%s, %s, %s, %s, %s, %s, 'tenant')
            """
            cursor.execute(query, (first_name, last_name, email, phone, password, landlord_id))
            connection.commit()

            flash('Tenant added successfully!', 'success')
            return redirect(url_for('landlord_dashboard'))  # Redirect to the landlord dashboard
        except mysql.connector.Error as e:
            flash(f"Error adding tenant: {e}", 'error')
            return redirect(url_for('landlord_add_tenant'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

    return render_template('add_tenant_landlord.html')  # Render the landlord's add tenant form

# Staff login
@app.route('/staff', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('stafflogin.html')

        try:
            # Verify user credentials
            staff = verify_user(email, password)
            if staff and staff['role'] == 'staff':
                # Log the user in
                login_user(User(staff['id'], staff['email'], staff['role']))
                flash('Login Successful!', 'success')
                return redirect(url_for('staff_input'))
            else:
                flash('Invalid email or password', 'error')
                return render_template('login_error.html')
        except Exception as e:
            flash(f"An error occurred during login: {e}", 'error')
            return render_template('login_staff.html')

    return render_template('stafflogin.html')
# Staff input page
@app.route('/staff-input') 
@login_required            
@role_required('staff')    
def staff_input():
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('staff_login'))

        cursor = connection.cursor(dictionary=True)

        # Fetch tenants with IDs starting with 'tent' and include their names
        query = """
                SELECT 
                    id AS tenant_id, 
                    CONCAT('tent', id, ' - ', first_name, ' ', last_name) AS display_name 
                    FROM users WHERE role = 'tenant'
                """
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

@app.route('/process_waste', methods=['POST'])
@login_required
@role_required('staff')  # Ensure only staff can access this route
def process_waste():
    try:
        # Retrieve form data
        tenant_id = request.form.get('tenant_id')
        waste_amount = request.form.get('waste_amount')

        # Validate input
        if not tenant_id or not waste_amount:
            flash("All fields are required!", "error")
            return redirect(url_for('staff_input'))

        # Establish database connection
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            return redirect(url_for('staff_input'))

        cursor = connection.cursor(dictionary=True)

        # Update the waste amount for the tenant
        update_query = """
            UPDATE users
            SET waste_amount = COALESCE(waste_amount, 0) + %s
            WHERE id = %s AND role = 'tenant'
        """
        cursor.execute(update_query, (waste_amount, tenant_id))
        connection.commit()

        flash("Waste data processed successfully!", "success")
        return redirect(url_for('success'))  # Redirect to the success page
    except mysql.connector.Error as e:
        flash(f"Error processing waste: {e}", "error")
        return redirect(url_for('staff_input'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/success')
@login_required
@role_required('staff')  
def success():
    return render_template('success.html')

# Tenant login
@app.route('/tenant', methods=['GET', 'POST'])
def tenant_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('login_tenant.html')

        try:
            # Verify user credentials
            tenant = verify_user(email, password)
            if tenant and tenant['role'] == 'tenant':
                # Log the user in
                login_user(User(tenant['id'], tenant['email'], tenant['role']))
                flash('Login Successful!', 'success')
                return redirect(url_for('tenant_dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return render_template('tenant_login_error.html')
        except Exception as e:
            flash(f"An error occurred during login: {e}", 'error')
            return render_template('login_tenant.html')

    return render_template('login_tenant.html')

# Tenant dashboard
@app.route('/tenant-dashboard')
@login_required
@role_required('tenant') 
def tenant_dashboard():
    tenant_id = current_user.id  # Get the ID of the logged-in tenant

    try:
        # Establish database connection
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", "error")
            return redirect(url_for('tenant_login'))

        cursor = connection.cursor(dictionary=True)

        # Fetch tenant-specific data from the `users` table
        query_tenant = "SELECT first_name, last_name, email, phone FROM users WHERE id = %s AND role = 'tenant'"
        cursor.execute(query_tenant, (tenant_id,))
        tenant = cursor.fetchone()  # Fetch tenant details

        if not tenant:
            flash("Tenant not found", "error")
            return redirect(url_for('tenant_login'))

        # Fetch waste data for the tenant from the `users` table
        query_waste = """
            SELECT 
                COALESCE(waste_amount, 0) AS total_kgs
            FROM users
            WHERE id = %s AND role = 'tenant'
        """
        cursor.execute(query_waste, (tenant_id,))
        waste_data = cursor.fetchone()  # Fetch waste data

        # Prepare data for the template
        tenant['name'] = f"{tenant['first_name']} {tenant['last_name']}"
        total_kgs = waste_data['total_kgs'] or 0

        return render_template(
            'dashboard_tenant.html',
            tenant=tenant,
            total_kgs=total_kgs
        )
    except mysql.connector.Error as e:
        flash(f"Error loading tenant dashboard: {e}", "error")
        return redirect(url_for('tenant_login'))
    finally:
        # Ensure resources are properly closed
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Edit tenant information                 
@app.route('/edit_tenant/<int:tenant_id>', methods=['POST'])
@login_required
@role_required('landlord')
def edit_tenant(tenant_id):
    try:
        connection = create_db_connection()
        if not connection:
            flash("Database connection error", 'error')
            return redirect(url_for('landlord_dashboard'))

        cursor = connection.cursor(dictionary=True)

        # Retrieve form data from the modal
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        # Validate input
        if not all([first_name, last_name, email, phone]):
            flash("All fields are required!", "error")
            return redirect(url_for('landlord_dashboard'))

        # Update tenant information in the centralized tenants table
        update_query = """
            UPDATE tenants
            SET first_name = %s, last_name = %s, email = %s, phone = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (first_name, last_name, email, phone, tenant_id))
        connection.commit()

        flash('Tenant information updated successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))

    except mysql.connector.Error as e:
        flash(f"Error editing tenant: {e}", 'error')
        return redirect(url_for('landlord_dashboard'))

    finally:
        # Ensure resources are properly closed
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/add_staff', methods=['POST'])
def add_staff():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password']
    
    hashed_password = generate_password_hash(password)

    conn = create_db_connection()
    cursor = conn.cursor()

    sql = "INSERT INTO users (first_name, last_name, email, phone, password, role) VALUES (%s, %s, %s, %s, %s, staff)"
    val = (first_name, last_name, email, phone, hashed_password)
    
    cursor.execute(sql, val)
    conn.commit()
    conn.close()

    flash("Staff added successfully!", "success")
    return redirect(url_for('staff_dashboard'))
            
            
@app.route('/staff_dashboard', methods=['GET'])
def staff_dashboard():
    # Establish a connection to the database
    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE role = 'staff'")
        staff_members = cursor.fetchall()
    except Exception as e:
        # Handle any errors that might occur during the query
        print(f"Error fetching staff members: {e}")
        staff_members = []

    # Close the database connection
    conn.close()

    # Render the staff_dashboard.html template with the staff data
    return render_template('staff_dashboard.html', staff_members=staff_members)

            
# Route for deleting staff
@app.route('/delete_staff/<int:staff_id>', methods=['GET'])
def delete_staff(staff_id):
    conn = create_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s AND role = 'staff'", (staff_id,))
        conn.commit()
        flash('Staff member deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting staff: {e}', 'danger')
        conn.rollback()
    finally:
        conn.close()

    return redirect(url_for('staff_dashboard'))
    
    
    
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


def find_user_by_email(email):
    try:
        connection = create_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        print(user)
        return user
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'connection' in locals(): connection.close()


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    source = request.args.get('source')

    if request.method == 'POST':
        email = request.form.get('email')
        user = find_user_by_email(email)

        if user:
            token = s.dumps(f"{email}|{source}", salt='recover-password')
            reset_link = url_for('reset_with_token', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f"Click the link below to reset your password:\n{reset_link}"
            mail.send(msg)

            flash('Password reset link sent to your email.', 'success')
            return redirect(url_for('pass_link_success'))
        else:
            flash('Invalid email address.', 'error')
            return redirect(url_for('reset_password', source=source))

    return render_template('reset_password.html', source=source)

@app.route('/Password-Reset-link-success')
def pass_link_success():
    return render_template('Resetlinksuccess.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        # Decode the token and extract email and source
        data = s.loads(token, salt='recover-password', max_age=200) 
        email, source = data.split('|')

    except (SignatureExpired, BadSignature, ValueError) as e:
        print(f"Token Error: {e}")
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('reset_password'))

    # POST request to handle the password reset
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match and are not empty
        if not new_password or new_password != confirm_password:
            flash('Passwords do not match or are empty.', 'error')
            return redirect(url_for('reset_with_token', token=token))

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        try:
            # Update password in the database
            connection = create_db_connection()
            cursor = connection.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            connection.commit()

            flash('Password reset successful.', 'success')
            return redirect(url_for('passwordresetsucessful'))

        except Exception as e:
            flash(f"Error resetting password: {e}", 'error')
            return redirect(url_for('reset_with_token', token=token))

        finally:
            if 'cursor' in locals(): cursor.close()
            if 'connection' in locals(): connection.close()

    return render_template('reset_with_token.html', token=token)

@app.route('/password-reset-sucessful')
def passwordresetsucessful():
    return render_template('passwordresetsucessful.html')

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
    session.pop('email', None)
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
    app.run(debug = True)
