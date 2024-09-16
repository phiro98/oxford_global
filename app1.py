from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///course_application1.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

db = SQLAlchemy()
db.init_app(app)
#check if path exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Simulated database
# forms_submitted = []
admin_username = 'admin'
admin_password_hash = generate_password_hash('admin_password')  # Replace 'admin_password' with your admin password

# Model for the course application
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    course = db.Column(db.String(100), nullable=False)
    comments = db.Column(db.Text)
    image_filename = db.Column(db.String(120), nullable=False)
    file_filename = db.Column(db.String(120), nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/create_admin')
def create_admin():
    # Define admin details
    username = 'admin'
    password = 'admin123'  # Change to your desired password
    
    # Hash the password for security
    hashed_password = generate_password_hash(password)
    
    # Check if admin already exists
    existing_admin = Admin.query.filter_by(username=username).first()
    if existing_admin:
        return "Admin already exists!"
    
    # Create a new admin user
    new_admin = Admin(username=username, password=hashed_password)
    db.session.add(new_admin)
    db.session.commit()
    
    return f'Admin {username} created with password {password}.'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_form', methods=['POST'])
def submit_form():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        course = request.form['course']
        comments = request.form['comments']

        # Handle image upload
        image = request.files['image']
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        # Handle file upload
        file = request.files['file']
        file_filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_filename))

        # Create new application entry in the database
        new_application = Application(firstname=firstname, lastname=lastname, email=email, course=course,
                                      comments=comments, image_filename=image_filename, file_filename=file_filename)
        db.session.add(new_application)
        db.session.commit()

        return  render_template('thank_you.html')

@app.route('/admin/view_submissions')
def view_submissions():
    if 'admin' not in session:
        flash('You need to log in first', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch applications from the database and pass to the template
    applications = Application.query.all()  # Example query
    return render_template('view_forms.html', applications=applications)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            session['admin'] = admin.username  # Store admin's username in the session
            flash('Login successful', 'success')
            return redirect(url_for('view_forms'))  # Redirect to the forms view or another page
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')


@app.route('/logout')
def logout():
    # Remove the admin from the session
    session.pop('admin', None)
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('admin_login'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Get the new password from the form
        new_password = request.form['new_password']

        # Validate that the password is at least 6 characters long
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('reset_password'))

        # Assuming we know which admin is resetting the password (e.g., via email link/token)
        admin_username = 'admin'  # This should be fetched dynamically based on the reset request.
        admin = Admin.query.filter_by(username=admin_username).first()

        if admin:
            # Hash the new password and update the database
            hashed_password = generate_password_hash(new_password)
            admin.password = hashed_password
            db.session.commit()

            flash('Your password has been successfully updated!', 'success')
            return render_template('admin_login.html')
        else:
            flash('Admin not found', 'danger')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')

# Thank you page after form submission
@app.route('/thank_you', methods=['GET'])
def thank_you():
    return render_template('thank_you.html')

# Admin login page
@app.route('/admin', methods=['GET'])
def admin():
    return render_template('admin_login.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
