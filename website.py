import os
import random
import string
import razorpay
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message  # <--- NEW IMPORT

# Initialize Flask
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app) 

# ==========================================
#  CONFIGURATION
# ==========================================

# 1. Database (PostgreSQL fix)
db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-key')

# 2. Razorpay
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_KEY')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', 'YOUR_SECRET')
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# 3. Email Configuration (Brevo SMTP)
# These defaults match your desktop app, but you should add them to Render Env Vars for security
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '9cd21d001@smtp-brevo.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'bskrnT85t4SOLS4')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', 'zarqeensoftware@gmail.com')

mail = Mail(app)
db = SQLAlchemy(app)

# ==========================================
#  DATABASE MODEL
# ==========================================
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)

# ==========================================
#  HELPER FUNCTIONS
# ==========================================
def generate_unique_key(plan_type):
    prefix = "BAS" if plan_type == 'basic' else "PRE"
    while True:
        part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        full_key = f"ZQ-{prefix}-{part1}-{part2}"
        if not License.query.filter_by(license_key=full_key).first():
            return full_key

# ==========================================
#  ROUTES
# ==========================================

@app.route('/')
def home():
    return render_template('index.html', key_id=RAZORPAY_KEY_ID)

# --- 1. Razorpay Routes ---
@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        amount = 29900 if plan == 'basic' else 59900 
        order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': '1'})
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
        new_key = generate_unique_key(plan_type)
        
        new_license = License(license_key=new_key, plan_type=plan_type, payment_id=data['razorpay_payment_id'])
        db.session.add(new_license)
        db.session.commit()

        return jsonify({'success': True, 'license_key': new_key})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'message': 'Payment Verification Failed'})

# --- 2. Desktop App: License Validation ---
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

# --- 3. Desktop App: Auto-Updater ---
@app.route('/api/latest_version')
def latest_version():
    return jsonify({
        "version": "1.3.0", # Update this when you release new software
        "download_url": "https://drive.google.com/drive/folders/17O3vY4KYUzd7Rma4o8rp3j2iIrpqhJe9?usp=drive_link",
        "release_notes": "Added License File support and fixed bugs."
    })

# --- 4. Desktop App: Remote Email Sender (The fix for your issue) ---
@app.route('/api/send_otp_remote', methods=['POST'])
def send_otp_remote():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    username = data.get('username', 'User')

    if not email or not otp:
        return jsonify({'success': False, 'error': 'Missing data'}), 400

    try:
        msg = Message("Zarqeen Verification Code", recipients=[email])
        msg.body = f"Hi {username},\n\nYour verification code is: {otp}\n\nThis code expires in 10 minutes."
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print(f"Mail Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
