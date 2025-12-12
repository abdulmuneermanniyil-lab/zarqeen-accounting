import os
import random
import string
import razorpay
from datetime import datetime
from functools import wraps # <--- Required for security
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message

app = Flask(__name__)
CORS(app)

# ==========================================
#  CONFIGURATION
# ==========================================

# 1. SECURITY KEY (Crucial for Login Sessions)
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING_IN_RENDER')

# 2. DATABASE
raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 3. RAZORPAY
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')

# 4. ADMIN CREDENTIALS
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# 5. MAIL
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', 'zarqeensoftware@gmail.com')

mail = Mail(app)
db = SQLAlchemy(app)
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# ==========================================
#  DATABASE MODEL
# ==========================================
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100), nullable=False)
    amount_paid = db.Column(db.Float, default=0.0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)

# Create tables
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"DB Error: {e}")

# ==========================================
#  SECURITY HELPER (The Lock)
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is NOT logged in
        if not session.get('admin_logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_unique_key(plan_type):
    prefix = "BAS" if plan_type == 'basic' else "PRE"
    while True:
        part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        full_key = f"ZQ-{prefix}-{part1}-{part2}"
        if not License.query.filter_by(license_key=full_key).first():
            return full_key

# ==========================================
#  PUBLIC ROUTES (Anyone can see)
# ==========================================
@app.route('/')
def home():
    return render_template('index.html', key_id=RAZORPAY_KEY_ID)

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        # Amount in Paise (30100 = 301.00 INR)
        amount = 29900 if plan == 'basic' else 59900
        order = razorpay_client.order.create({
            'amount': amount, 
            'currency': 'INR', 
            'payment_capture': '1'
        })
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json
    try:
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        plan_type = data.get('plan_type')
        amount = 299.0 if plan_type == 'basic' else 599.0
        new_key = generate_unique_key(plan_type)
        
        new_license = License(
            license_key=new_key, 
            plan_type=plan_type, 
            payment_id=data['razorpay_payment_id'],
            amount_paid=amount
        )
        db.session.add(new_license)
        db.session.commit()

        return jsonify({'success': True, 'license_key': new_key})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'message': str(e)})

# ==========================================
#  ADMIN ROUTES (PROTECTED 🔒)
# ==========================================

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    # If already logged in, go to dashboard
    if session.get('admin_logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials', 'danger')
    return render_template('login.html')

@app.route('/admin/dashboard')
@login_required  # <--- THIS LOCKS THE DASHBOARD
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    return render_template('dashboard.html', licenses=licenses)

@app.route('/admin/delete_license/<int:id>', methods=['POST'])
@login_required # <--- THIS LOCKS DELETION
def delete_license(id):
    lic = License.query.get_or_404(id)
    try:
        db.session.delete(lic)
        db.session.commit()
        flash('License deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_license/<int:id>', methods=['POST'])
@login_required # <--- THIS LOCKS EDITING
def edit_license(id):
    lic = License.query.get_or_404(id)
    try:
        lic.license_key = request.form.get('license_key')
        lic.plan_type = request.form.get('plan_type')
        lic.payment_id = request.form.get('payment_id')
        
        is_used_val = request.form.get('is_used')
        lic.is_used = True if is_used_val == 'on' else False
        
        if not lic.is_used:
            lic.used_at = None
            
        db.session.commit()
        flash('License updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('login'))

# ==========================================
#  SOFTWARE API (For Windows App)
# ==========================================
@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json
    key_input = data.get('license_key', '').strip()
    lic = License.query.filter_by(license_key=key_input).first()
    
    if lic:
        if lic.is_used:
            return jsonify({'valid': False, 'message': 'License already used.'})
        lic.is_used = True
        lic.used_at = datetime.utcnow()
        db.session.commit()
        duration = 365 if lic.plan_type == 'basic' else 1095
        return jsonify({'valid': True, 'plan': lic.plan_type, 'duration_days': duration})
    
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

@app.route('/api/send_otp_remote', methods=['POST'])
def send_otp_remote():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    if not email or not otp: return jsonify({'success': False}), 400
    try:
        msg = Message("Zarqeen Verification Code", recipients=[email])
        msg.body = f"Code: {otp}"
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
