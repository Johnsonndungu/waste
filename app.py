from binascii import Error
from functools import wraps
from flask import Flask, flash, redirect, render_template, jsonify, request, session, url_for
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = "mnndnkjkfkslkklakljkdfkjreoirfjdkfkdjgjkfdgjkd"


# Database Connection
def create_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="Root",
            database="waste"
)
    except Error as e:
        print(f'Error connecting to MySQL DB: {e}')
        return None
    
# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash('Please log in first.','warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Validating user is in db
def verify_user(Email, password):
    try:
        connection = create_db_connection()
        if not connection:
            flash("Databse connection error",'error')
            return None
        
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE Email=%s AND password=%s"
        cursor.execute(query,(Email, password))
        user = cursor.fetchone()
        return user
    except Error as e:
        print(f"Error Verifying user:: {e}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Landlord Login
@app.route('/landlord', methods=['GET', 'POST'])
def landlord_login():
    if request.method == 'POST':
        Email = request.form.get('Email')
        password = request.form.get('password')

        if not Email or not password:
            flash('Please provide both Email and password', 'Error')
            return redirect(url_for('landlord_login'))
        
        landlord = verify_user(Email, password)
        if landlord:
            session['landlord_id'] = landlord['id']
            session['Email'] = landlord['Email']
            flash('Login Successful!','Success')
            return redirect(url_for('landlord_dashboard'))
        else:
            flash('Invalid Email or password. Please try again.', 'error')
            return redirect(url_for('landlord_login'))
        
    return render_template('login_landlord.html')

# Landlord dashboard
@app.route('/landlord_dashboard')
@login_required
def admin_dashboard():
    try:
        connection = create_db_connection()
        if not connection:
            flash('Database connection error', 'error')
            return redirect(url_for('landlord_login'))
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT * From tenants')
        tenants = cursor.fetchall()
        return render_template('dashboard_landlord.html', tenants=tenants)
    except Error as e:
        flash(f'An error occurred: {e}', 'error')
        return redirect(url_for('landlord_login'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Logout button

if __name__ == '__main__':
    app.run(debug=True)