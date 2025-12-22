import os
import random
import string
import razorpay
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE_THIS_SECRET')

# Database
raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Razorpay
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')

# Admin Auth
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', 'zarqeensoftware@gmail.com')

# --- 2. ENABLE CORS ---
# This allows your Static Site (zarqeen.in) to fetch data from this Backend
CORS(app, resources={r"/*": {"origins": "*"}})

mail = Mail(app)
db = SQLAlchemy(app)
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- 3. DATABASE MODELS ---
# --- 3. DATABASE MODELS ---
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    
    # Auth Fields
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    discount_percent = db.Column(db.Integer, default=10)
    
    # Commission/Earnings Logic (Optional: Calculate earnings based on sales)
    licenses = db.relationship('License', backref='distributor', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100), nullable=False)
    amount_paid = db.Column(db.Float, default=0.0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)
    # Link to Distributor
    distributor_id = db.Column(db.Integer, db.ForeignKey('distributor.id'), nullable=True)

with app.app_context():
    try:
        db.create_all()
        # Create a default distributor for testing if none exists
        if not Distributor.query.first():
            demo = Distributor(code="ZARQEEN10", name="Official Support", phone="zarqeensoftware@gmail.com", discount_percent=10)
            db.session.add(demo)
            db.session.commit()
    except Exception as e:
        print(f"DB Error: {e}")

# --- 4. HELPER FUNCTIONS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
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
#  PUBLIC API ROUTES (Called by Frontend)
# ==========================================

@app.route('/')
def home():
    # If someone visits the Backend URL directly, send them to Admin Login
    return redirect(url_for('login'))

@app.route('/api/get-config', methods=['GET'])
def get_config():
    """ Sends Razorpay Key to Frontend securely """
    return jsonify({'key_id': RAZORPAY_KEY_ID})




@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        code = data.get('distributor_code', '').strip().upper() # Get code from frontend

        # Base Prices (in Paise)
        base_amount = 29900 if plan == 'basic' else 59900
        
        # Check for Distributor Discount
        dist = Distributor.query.filter_by(code=code).first()
        final_amount = base_amount
        
        if dist:
            discount_amount = (base_amount * dist.discount_percent) / 100
            final_amount = int(base_amount - discount_amount)
        
        order = razorpay_client.order.create({
            'amount': final_amount, 
            'currency': 'INR', 
            'payment_capture': '1',
            'notes': {
                'plan': plan,
                'distributor_id': dist.id if dist else None
            }
        })
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json
    try:
        # 1. Verify Signature (Keep existing code)
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        # 2. Get Order Details from Razorpay to find the Distributor ID
        # (We stored it in notes during create_order)
        order_info = razorpay_client.order.fetch(data['razorpay_order_id'])
        distributor_id = order_info['notes'].get('distributor_id')
        
        if distributor_id == 'None': distributor_id = None

        # 3. Generate License
        plan_type = data.get('plan_type')
        amount_paid = order_info['amount'] / 100 # Convert back to Rupees
        new_key = generate_unique_key(plan_type)
        
        new_license = License(
            license_key=new_key, 
            plan_type=plan_type, 
            payment_id=data['razorpay_payment_id'],
            amount_paid=amount_paid,
            distributor_id=distributor_id  # <--- SAVE ID HERE
        )
        db.session.add(new_license)
        db.session.commit()

        return jsonify({'success': True, 'license_key': new_key})

    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json
    key_input = data.get('license_key', '').strip()
    lic = License.query.filter_by(license_key=key_input).first()
    
    if lic:
        if lic.is_used:
            return jsonify({'valid': False, 'message': 'License already used.'})
        
        # Mark as used
        lic.is_used = True
        lic.used_at = datetime.utcnow()
        db.session.commit()
        
        duration = 365 if lic.plan_type == 'basic' else 1095
        
        # Fetch Distributor Details if they exist
        support_name = "Zarqeen Official"
        support_contact = "zarqeensoftware@gmail.com"
        
        if lic.distributor:
            support_name = lic.distributor.name
            support_contact = lic.distributor.phone

        return jsonify({
            'valid': True, 
            'plan': lic.plan_type, 
            'duration_days': duration,
            'support_info': {
                'name': support_name,
                'contact': support_contact
            }
        })
    
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

# ==========================================
#  ADMIN PANEL (Server-Side Rendering)
# ==========================================

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
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
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    return render_template('dashboard.html', licenses=licenses)

@app.route('/admin/delete_license/<int:id>', methods=['POST'])
@login_required
def delete_license(id):
    lic = License.query.get_or_404(id)
    db.session.delete(lic)
    db.session.commit()
    flash('License deleted', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_license/<int:id>', methods=['POST'])
@login_required
def edit_license(id):
    lic = License.query.get_or_404(id)
    lic.license_key = request.form.get('license_key')
    lic.plan_type = request.form.get('plan_type')
    lic.payment_id = request.form.get('payment_id')
    lic.is_used = True if request.form.get('is_used') == 'on' else False
    if not lic.is_used: lic.used_at = None
    db.session.commit()
    flash('License updated', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin/add_distributor', methods=['POST'])
@login_required
def add_distributor():
    code = request.form.get('code')
    name = request.form.get('name')
    phone = request.form.get('phone')
    disc = request.form.get('discount')
    
    new_dist = Distributor(code=code, name=name, phone=phone, discount_percent=int(disc))
    db.session.add(new_dist)
    db.session.commit()
    flash('Distributor added!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('login'))

@app.route('/api/check_distributor', methods=['POST'])
def check_distributor():
    data = request.json
    code = data.get('code', '').strip().upper()
    dist = Distributor.query.filter_by(code=code).first()
    
    if dist:
        return jsonify({
            'valid': True, 
            'discount': dist.discount_percent,
            'name': dist.name
        })
    return jsonify({'valid': False})

# ==========================================
#  DESKTOP APP API
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


# ==========================================
#  DISTRIBUTOR PORTAL ROUTES
# ==========================================

@app.route('/distributor/login', methods=['GET', 'POST'])
def distributor_login():
    if session.get('distributor_id'):
        return redirect(url_for('distributor_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        dist = Distributor.query.filter_by(username=username).first()
        
        if dist and dist.check_password(password):
            session['distributor_id'] = dist.id
            session['distributor_name'] = dist.name
            return redirect(url_for('distributor_dashboard'))
        else:
            flash('Invalid Username or Password', 'danger')
            
    return render_template('distributor_login.html')

@app.route('/distributor/dashboard')
def distributor_dashboard():
    if not session.get('distributor_id'):
        return redirect(url_for('distributor_login'))
    
    dist_id = session['distributor_id']
    dist = Distributor.query.get(dist_id)
    
    # Fetch licenses linked to this distributor
    # "Pending" here implies keys generated but not yet used by the customer
    my_sales = License.query.filter_by(distributor_id=dist_id).order_by(License.created_at.desc()).all()
    
    total_sales = len(my_sales)
    # Calculate simple commission (e.g., 20% of revenue generated)
    total_revenue = sum(lic.amount_paid for lic in my_sales)
    commission = total_revenue * 0.20 # Assuming distributor gets 20% cut
    
    return render_template('distributor_dashboard.html', 
                           distributor=dist, 
                           sales=my_sales, 
                           total_sales=total_sales,
                           commission=commission)

@app.route('/distributor/logout')
def distributor_logout():
    session.pop('distributor_id', None)
    session.pop('distributor_name', None)
    return redirect(url_for('distributor_login'))


if __name__ == '__main__':
    app.run(debug=True)
