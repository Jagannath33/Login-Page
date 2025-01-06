# Flask OTP Verification Web Application  

## Overview  
This Flask-based application enables users to register, receive a One-Time Password (OTP) via email, and verify their identity through OTP input. It features secure user authentication, email-based registration validation, and a protected dashboard accessible only to verified users. The OTP is time-sensitive, adding an extra layer of security.  

## Key Features  
### 1. OTP-Enabled User Registration  
Users sign up with a username, email, and password. An OTP is sent to their registered email for verification.  

### 2. Time-Limited OTP  
The OTP expires after 2 minutes. Users must re-register or request a new OTP if it expires.  

### 3. User Login  
Once verified, users can log in with their email and password.  

## Technologies Used  

### Frontend  
- **HTML5**: Provides structure to the web pages.  
- **CSS**: Handles styling and responsive design.  
- **JavaScript**: Adds interactivity and form validation.  

### Backend  
- **Python**: Powers the core logic and app structure.  
- **Flask**: Manages routing, session control, and backend logic.  

### Database  
- **SQLite**: A lightweight database to store user and OTP data.  

## Installation and Usage  

### Prerequisites  
- Python 3.x installed on your system.  
- Pip (Python package manager) installed.  

### Installation Steps  

1. **Clone the Repository**  
   ```bash  
   git clone <repository-url>  
   cd <repository-folder>  
   ```  

2. **Install Dependencies**  
   ```bash
   pip install Flask==3.0.3 Flask-SQLAlchemy==3.1.1 Flask-Login==0.6.3 Flask-Mail==0.9.1 Werkzeug==3.0.4 bcrypt==4.0.1

   ```  

3. **Database Setup**  
   The database is initialized automatically when the application runs for the first time. No manual setup is needed.  

4. **Configure Email for OTP Sending**  
   - Use a Gmail account to send OTPs.  
   - Enable **App Passwords** in Gmail for secure email handling.  
   - Update your email credentials in the app:  
   ```python  
   app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  
   app.config['MAIL_PASSWORD'] = 'your-app-password'  
   ```  

### Usage  

1. **Run the Application**  
   ```bash  
   python app.py  
   ```  

2. **Access the App**  
   Open a browser and go to [http://127.0.0.1:5000](http://127.0.0.1:5000/).  

3. **Register a New User**  
   - Enter a username, email, and password.  
   - An OTP will be sent to the provided email.  

4. **Verify OTP**  
   - Enter the OTP to complete the registration process.  

5. **Login**  
   - Use your registered email and password to log in.  

   - Access the us!
er dashboard.  

6. **Logout**  
   - Click the logout button to end your session.  

## Screenshots  
![Screenshot_20241204_101027](https://github.com/user-attachments/assets/061a9d7d-1819-4240-accd-41daffe8f209)
![Screenshot 2025-01-06 094125](https://github.com/user-attachments/assets/3bdc6e24-6e84-48e8-a235-6d1b34b2d9d2)
![Screenshot_20241204_102958](https://github.com/user-attachments/assets/a3d9b446-7442-4bf3-b373-d2b63ec69cf7)
![Screenshot 2025-01-06 094716](https://github.com/user-attachments/assets/ebb61493-c37f-46a7-8509-ebf4b322bda3)
![Screenshot 2025-01-06 092718](https://github.com/user-attachments/assets/37e57942-cc18-4a0d-9f80-79298ffa3896)










