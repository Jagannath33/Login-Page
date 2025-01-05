from flask import Flask, request, render_template, session, redirect, url_for, flash  # Core Flask imports
from flask_sqlalchemy import SQLAlchemy  # For database operations
import bcrypt  # For hashing and verifying passwords
import random  # To generate random numbers (used in OTP generation)
import string  # Provides character sets like digits, alphabets, etc.
from datetime import datetime, timedelta  # For handling time and OTP expiration
from flask_mail import Mail, Message  # For sending emails
import os  # To access environment variables
from dotenv import load_dotenv  # To load environment variables from a .env file

# Load environment variables from .env file
load_dotenv()

# Flask app initialization
app = Flask(__name__)
app.secret_key = 'SECRET_KEY'  # Used to secure session data

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disables modification tracking for performance
db = SQLAlchemy(app)  # Initialize the SQLAlchemy object

# Email Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # SMTP server address for Gmail
app.config['MAIL_PORT'] = 587  # Port for TLS communication
app.config['MAIL_USE_TLS'] = True  # Use TLS (Transport Layer Security)
app.config['MAIL_USE_SSL'] = False  # SSL is disabled since we're using TLS
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_SENDER')  # Email address (from .env)
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSKEY')  # Email password or app-specific passkey (from .env)
mail = Mail(app)  # Initialize Flask-Mail

# User model for storing user information
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each user
    username = db.Column(db.String(80), unique=True, nullable=False)  # Username (must be unique)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email (must be unique)
    password = db.Column(db.String(120), nullable=False)  # Hashed password

# OTP model for storing OTP details
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each OTP
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email associated with the OTP
    otp_code = db.Column(db.String(6), nullable=False)  # 6-digit OTP code
    expires_at = db.Column(db.DateTime, nullable=False)  # Expiration time for the OTP
    failed_attempts = db.Column(db.Integer, default=0)  # Tracks failed OTP verification attempts

# Create tables in the database (for testing and setup)
# Uncomment the lines below if running the app for the first time
with app.app_context():
    db.drop_all()  # Optional: Drops all tables (use cautiously)
    db.create_all()  # Creates tables based on the defined models

# Function to send OTP to a user's email
def send_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))  # Generate a random 6-digit OTP
    expires_at = datetime.now() + timedelta(minutes=2)  # OTP expires in 2 minutes

    otp_record = OTP.query.filter_by(email=email).first()  # Check if OTP already exists for the email
    if otp_record:
        # Update existing OTP record
        otp_record.otp_code = otp
        otp_record.expires_at = expires_at
    else:
        # Create a new OTP record if none exists
        otp_record = OTP(email=email, otp_code=otp, expires_at=expires_at)
        db.session.add(otp_record)

    db.session.commit()  # Save changes to the database

    # Send OTP via email
    msg = Message('Your OTP Code', sender='Your Email Address', recipients=[email])
    msg.body = f'Your OTP code is {otp}. It will expire in 2 minutes.'
    mail.send(msg)  # Send the email

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']  # Get email from the form
        password = request.form['password']  # Get password from the form
        user = User.query.filter_by(email=email).first()  # Fetch user record

        # Verify the password
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')): 
            session['email'] = email  # Save user email in session
            session['logged_in'] = True  # Mark user as logged in
            return redirect(url_for('dashboard'))  # Redirect to dashboard

        flash('Invalid Credentials', 'error')  # Show error message
        return redirect(url_for('login'))

    return render_template('login.html')  # Render login page

# Registration route with OTP
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['name']  # Get username
        email = request.form['email']  # Get email
        password = request.form['password']  # Get password
        confirm_password = request.form['password2']  # Confirm password

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered", "error")
            return redirect(url_for('login'))

        # Temporarily save OTP for verification
        send_otp(email)
        session['email'] = email
        session['username'] = username
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))  # Hash password
        session['password'] = hashed_password.decode('utf-8')  # Store hashed password in session
        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for('otpverify'))

    return render_template('register.html')

# OTP verification route
@app.route('/otpverify', methods=['GET', 'POST'])
def otpverify():
    if request.method == 'POST':
        otp = request.form['otp']  # Get OTP from the form
        email = session.get('email')  # Get email from session
        username = session.get('username')  # Get username from session
        password = session.get('password')  # Get password from session

        if not email or not username or not password:
            flash("Session expired or invalid request.", "error")
            return redirect(url_for('register'))

        otp_record = OTP.query.filter_by(email=email).first()

        if otp_record and otp_record.failed_attempts >= 5:
            flash('Too many failed attempts. Please try again later.', 'error')
            return redirect(url_for('register'))

        if not otp_record or otp != otp_record.otp_code or datetime.now() > otp_record.expires_at:
            flash('Invalid or expired OTP', 'error')
            return redirect(url_for('otpverify'))

        otp_record.failed_attempts = 0
        db.session.commit()

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        db.session.delete(otp_record)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('otpverify.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_email = session.get('email')
    user = User.query.filter_by(email=user_email).first()

    return render_template('dashboard.html', username=user.username)

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

# Add security headers to responses
@app.after_request
def add_cache_control_headers(response):
    if 'logged_in' in session:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)









