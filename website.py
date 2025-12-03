import os
import random
import string
import razorpay
import hmac
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# Initialize Flask
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app) # Allows your desktop app to talk to this website

# ==========================================
#  CONFIGURATION
# ==========================================

# 1. Database Configuration (Handles Render PostgreSQL fix)
# Render provides 'postgres://' but SQLAlchemy requires 'postgresql://'
db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')

# 2. Razorpay Configuration (Get these from Render Environment Variables)
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_TEST_KEY')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', 'YOUR_SECRET_KEY')

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
db = SQLAlchemy(app)

# ==========================================
#  DATABASE MODEL
# ==========================================
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False) # 'basic' or 'premium'
    payment_id = db.Column(db.String(100), nullable=False)
    is_used = db.Column(db.Boolean, default=False) # False = New, True = Used in App
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)

# ==========================================
#  HELPER FUNCTIONS
# ==========================================
def generate_unique_key(plan_type):
    """Generates a key like ZQ-BAS-XK92-MM31"""
    prefix = "BAS" if plan_type == 'basic' else "PRE"
    
    while True:
        # Generate random parts
        part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        full_key = f"ZQ-{prefix}-{part1}-{part2}"
        
        # Ensure it doesn't already exist in DB
        if not License.query.filter_by(license_key=full_key).first():
            return full_key

# ==========================================
#  ROUTES
# ==========================================

@app.route('/')
def home():
    """Serves the Landing Page"""
    return render_template('index.html', key_id=RAZORPAY_KEY_ID)

@app.route('/create_order', methods=['POST'])
def create_order():
    """Initializes a Razorpay Order"""
    try:
        data = request.json
        plan = data.get('plan') # 'basic' or 'premium'
        
        # Amount in paise (100 paise = 1 Rupee)
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
    """Verifies payment signature and Generates License"""
    data = request.json
    try:
        # 1. Verify Signature
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        # 2. Payment Successful -> Generate License
        plan_type = data.get('plan_type')
        new_key = generate_unique_key(plan_type)
        
        # 3. Save to Database
        new_license = License(
            license_key=new_key, 
            plan_type=plan_type, 
            payment_id=data['razorpay_payment_id']
        )
        db.session.add(new_license)
        db.session.commit()

        return jsonify({'success': True, 'license_key': new_key})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'message': 'Payment Verification Failed'})

# ==========================================
#  API FOR DESKTOP APP
# ==========================================
@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    """Called by the Desktop Software to check if key is valid"""
    data = request.json
    key_input = data.get('license_key', '').strip()
    
    lic = License.query.filter_by(license_key=key_input).first()
    
    if lic:
        if lic.is_used:
            return jsonify({'valid': False, 'message': 'This license key has already been used.'})
        
        # Mark as used so it cannot be shared
        lic.is_used = True
        lic.used_at = datetime.utcnow()
        db.session.commit()
        
        # Return plan details to the desktop app
        duration = 365 if lic.plan_type == 'basic' else 1095 # 1 year vs 3 years
        
        return jsonify({
            'valid': True, 
            'plan': lic.plan_type, 
            'duration_days': duration,
            'message': 'License Activated Successfully'
        })
    
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

# Initialize DB (Auto-create tables)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)