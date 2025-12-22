import os
import random
import string
import secrets
import razorpay
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE_THIS_SECRET')
FRONTEND_URL = "https://zarqeen.in"

# Cookie Settings for Cross-Origin Login
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None 
)

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

# Mail Configuration (REQUIRED for Forgot Password)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com') # Example
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', os.environ.get('MAIL_USERNAME'))

# CORS
CORS(app, 
     resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, 
     supports_credentials=True)

mail = Mail(app)
db = SQLAlchemy(app)
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- 3. DATABASE MODELS ---
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    
    # Changed Username to Email
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    discount_percent = db.Column(db.Integer, default=10)
    
    # Auth & Reset Tokens
    api_token = db.Column(db.String(100), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    
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
    distributor_id = db.Column(db.Integer, db.ForeignKey('distributor.id'), nullable=True)

with app.app_context():
    try:
        db.create_all()
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
#  PUBLIC API ROUTES
# ==========================================

@app.route('/')
def home():
    return redirect(FRONTEND_URL)

@app.route('/api/get-config', methods=['GET'])
def get_config():
    return jsonify({'key_id': RAZORPAY_KEY_ID})

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

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        code = data.get('distributor_code', '').strip().upper() 

        base_amount = 29900 if plan == 'basic' else 59900
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
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        order_info = razorpay_client.order.fetch(data['razorpay_order_id'])
        distributor_id = order_info['notes'].get('distributor_id')
        if distributor_id == 'None': distributor_id = None

        plan_type = data.get('plan_type')
        amount_paid = order_info['amount'] / 100 
        new_key = generate_unique_key(plan_type)
        
        new_license = License(
            license_key=new_key, 
            plan_type=plan_type, 
            payment_id=data['razorpay_payment_id'],
            amount_paid=amount_paid,
            distributor_id=distributor_id
        )
        db.session.add(new_license)
        db.session.commit()
        return jsonify({'success': True, 'license_key': new_key})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

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
        
        support_name = "Zarqeen Official"
        support_contact = "zarqeensoftware@gmail.com"
        if lic.distributor:
            support_name = lic.distributor.name
            support_contact = lic.distributor.phone

        return jsonify({'valid': True, 'plan': lic.plan_type, 'duration_days': duration, 'support_info': {'name': support_name, 'contact': support_contact}})
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

# ==========================================
#  ADMIN PANEL
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
    distributors = Distributor.query.all() # Fetch distributors for admin control
    return render_template('dashboard.html', licenses=licenses, distributors=distributors)

@app.route('/admin/delete_license/<int:id>', methods=['POST'])
@login_required
def delete_license(id):
    lic = License.query.get_or_404(id)
    db.session.delete(lic)
    db.session.commit()
    flash('License deleted', 'success')
    return redirect(url_for('dashboard'))

# --- ADMIN: DISTRIBUTOR CONTROL ---
@app.route('/admin/add_distributor', methods=['POST'])
@login_required
def add_distributor():
    try:
        code = request.form.get('code')
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email') # Changed from username
        password = request.form.get('password')
        disc = request.form.get('discount')
        
        if Distributor.query.filter((Distributor.code==code) | (Distributor.email==email)).first():
            flash('Error: Distributor Code or Email already exists.', 'danger')
            return redirect(url_for('dashboard'))

        new_dist = Distributor(
            code=code, name=name, phone=phone, email=email, discount_percent=int(disc)
        )
        new_dist.set_password(password)
        db.session.add(new_dist)
        db.session.commit()
        flash('Distributor added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding distributor: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_distributor/<int:id>', methods=['POST'])
@login_required
def delete_distributor(id):
    dist = Distributor.query.get_or_404(id)
    # Optional: Delete associated licenses or keep them? Keeping them for now but setting dist_id to null
    licenses = License.query.filter_by(distributor_id=id).all()
    for l in licenses:
        l.distributor_id = None
    db.session.delete(dist)
    db.session.commit()
    flash('Distributor deleted', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(FRONTEND_URL)

# ==========================================
#  DISTRIBUTOR & PASSWORD RESET (TOKEN BASED)
# ==========================================

@app.route('/api/distributor/login', methods=['POST'])
def api_distributor_login():
    data = request.json
    email = data.get('email') # Changed to email
    password = data.get('password')
    
    dist = Distributor.query.filter_by(email=email).first()
    
    if dist and dist.check_password(password):
        token = secrets.token_hex(16)
        dist.api_token = token
        db.session.commit()
        return jsonify({'success': True, 'token': token})
    
    return jsonify({'success': False, 'message': 'Invalid Email or Password'})

@app.route('/api/distributor/data', methods=['GET'])
def api_get_distributor_data():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1] if auth_header else None
    
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({'error': 'Invalid Token'}), 401
    
    sales = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc()).all()
    sales_data = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key} for s in sales]
    
    return jsonify({
        'name': dist.name, 'code': dist.code, 'discount': dist.discount_percent,
        'total_sales': len(sales), 'commission': sum(s.amount_paid for s in sales) * 0.20,
        'sales_history': sales_data
    })

# --- FORGOT PASSWORD FLOW ---
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    dist = Distributor.query.filter_by(email=email).first()
    if not dist:
        return jsonify({'success': False, 'message': 'Email not found'})
    
    reset_token = secrets.token_urlsafe(32)
    dist.reset_token = reset_token
    db.session.commit()
    
    reset_url = url_for('reset_password_page', token=reset_token, _external=True)
    
    try:
        msg = Message('Password Reset Request - Zarqeen', recipients=[email])
        msg.body = f"Click here to reset your password: {reset_url}"
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Reset link sent to email'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error sending email: {str(e)}'})

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    dist = Distributor.query.filter_by(reset_token=token).first()
    if not dist:
        return "Invalid or Expired Token"
        
    if request.method == 'POST':
        new_pass = request.form.get('password')
        dist.set_password(new_pass)
        dist.reset_token = None # Clear token
        db.session.commit()
        return "<h1>Password Updated!</h1><p>You can now login at zarqeen.in</p>"
        
    return render_template('reset_password.html', token=token)

# ==========================================
#  DB RESET
# ==========================================
@app.route('/reset-db-now')
def reset_database_force():
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
            if not Distributor.query.first():
                demo = Distributor(
                    code="DEMO", name="Demo Distributor", phone="9999999999",
                    email="demo@gmail.com", discount_percent=10
                )
                demo.set_password("demo123")
                db.session.add(demo)
                db.session.commit()
        return "<h1>✅ Database Reset!</h1><p>New columns: email, reset_token added.</p>"
    except Exception as e:
        return f"<h1>❌ Error: {e}</h1>"

if __name__ == '__main__':
    app.run(debug=True)
