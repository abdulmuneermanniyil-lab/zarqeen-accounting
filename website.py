import os
import random
import string
import secrets
import csv
import io
import razorpay
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURATION ---
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE_THIS_SECRET')
FRONTEND_URL = "https://zarqeen.in"

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None 
)

raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', os.environ.get('MAIL_USERNAME'))

CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)

mail = Mail(app)
db = SQLAlchemy(app)
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- DATABASE MODELS ---
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    discount_percent = db.Column(db.Integer, default=10)
    
    # Banking & Commission
    bank_details = db.Column(db.String(500), nullable=True) 
    upi_id = db.Column(db.String(100), nullable=True)       
    commission_paid = db.Column(db.Float, default=0.0)      
    
    api_token = db.Column(db.String(100), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    licenses = db.relationship('License', backref='distributor', lazy=True)

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

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
    db.create_all()

# --- HELPERS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_unique_key(plan_type, dist_code=None):
    plan_str = "BAS" if plan_type == 'basic' else "PRE"
    d_part = dist_code.upper()[:4] if dist_code else "ZARQ"
    d_part = d_part.ljust(4, 'X') 
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    full_key = f"ZQ-{d_part}-{plan_str}-{part1}{part2}"
    if License.query.filter_by(license_key=full_key).first(): return generate_unique_key(plan_type, dist_code)
    return full_key

# --- PUBLIC ROUTES ---
@app.route('/')
def home(): return redirect(FRONTEND_URL)

@app.route('/api/get-config', methods=['GET'])
def get_config(): return jsonify({'key_id': RAZORPAY_KEY_ID})

@app.route('/api/check_distributor', methods=['POST'])
def check_distributor():
    data = request.json
    code = data.get('code', '').strip().upper()
    dist = Distributor.query.filter_by(code=code).first()
    if dist: return jsonify({'valid': True, 'discount': dist.discount_percent, 'name': dist.name})
    return jsonify({'valid': False})

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        code = data.get('distributor_code', '').strip().upper() if data.get('distributor_code') else ""
        base_amount = 29900 if plan == 'basic' else 59900
        dist = Distributor.query.filter_by(code=code).first() if code else None
        
        final_amount = base_amount
        dist_id_str = "None"
        if dist:
            final_amount = int(base_amount - ((base_amount * dist.discount_percent) / 100))
            dist_id_str = str(dist.id)
        
        order = razorpay_client.order.create({
            'amount': final_amount, 'currency': 'INR', 'payment_capture': '1',
            'notes': {'plan': str(plan), 'distributor_id': dist_id_str}
        })
        return jsonify(order)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        })
        order_info = razorpay_client.order.fetch(data['razorpay_order_id'])
        dist_id_val = order_info['notes'].get('distributor_id')
        dist_obj = Distributor.query.get(int(dist_id_val)) if dist_id_val and dist_id_val != "None" else None
        
        new_key = generate_unique_key(data.get('plan_type'), dist_obj.code if dist_obj else None)
        new_license = License(
            license_key=new_key, plan_type=data.get('plan_type'), payment_id=data['razorpay_payment_id'],
            amount_paid=order_info['amount'] / 100, distributor_id=dist_obj.id if dist_obj else None
        )
        db.session.add(new_license)
        db.session.commit()
        return jsonify({'success': True, 'license_key': new_key})
    except Exception as e: return jsonify({'success': False, 'message': str(e)})

# --- NEW DOWNLOAD ROUTES ---
@app.route('/download/license/<key>')
def download_license_file(key):
    return send_file(
        io.BytesIO(key.encode()),
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'license_{key}.zarqeen'
    )

@app.route('/admin/export/<type>')
@login_required
def export_data(type):
    si = io.StringIO()
    cw = csv.writer(si)
    
    if type == 'licenses':
        cw.writerow(['Date', 'Key', 'Plan', 'Amount', 'Distributor', 'Status'])
        records = License.query.all()
        for r in records:
            d_name = r.distributor.name if r.distributor else 'Direct'
            cw.writerow([r.created_at, r.license_key, r.plan_type, r.amount_paid, d_name, r.is_used])
            
    elif type == 'distributors':
        cw.writerow(['Name', 'Code', 'Email', 'Phone', 'Bank', 'UPI', 'Total Earned', 'Paid', 'Balance'])
        records = Distributor.query.all()
        for r in records:
            total_earned = sum(l.amount_paid for l in r.licenses) * 0.20
            balance = total_earned - r.commission_paid
            cw.writerow([r.name, r.code, r.email, r.phone, r.bank_details, r.upi_id, total_earned, r.commission_paid, balance])
            
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=export_{type}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# --- ADMIN PANEL ---
@app.route('/admin/dashboard')
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    
    dist_data = []
    for d in distributors:
        earned = sum(l.amount_paid for l in d.licenses) * 0.20
        balance = earned - d.commission_paid
        dist_data.append({'obj': d, 'earned': earned, 'balance': balance})
        
    return render_template('dashboard.html', licenses=licenses, distributors=dist_data)

# --- UPDATE THIS ROUTE ---
@app.route('/admin/add_distributor', methods=['POST'])
@login_required
def add_distributor():
    try:
        # 1. Clean Inputs
        code = request.form.get('code', '').strip().upper()
        email = request.form.get('email', '').strip().lower()
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '').strip()
        
        # Handle Discount (Default to 10 if empty)
        disc_raw = request.form.get('discount')
        discount = int(disc_raw) if disc_raw and disc_raw.isnumeric() else 10

        # 2. Validation
        if not code or not email or not password:
            flash('Error: Name, Code, Email, and Password are required.', 'danger')
            return redirect(url_for('dashboard'))

        if len(code) != 4:
            flash('Error: Code must be exactly 4 letters.', 'danger')
            return redirect(url_for('dashboard'))

        # 3. Check Duplicates
        if Distributor.query.filter((Distributor.code==code) | (Distributor.email==email)).first():
            flash('Error: Distributor Code or Email already exists.', 'danger')
            return redirect(url_for('dashboard'))
        
        # 4. Create Record
        new_dist = Distributor(
            code=code, 
            name=name, 
            phone=phone,
            email=email, 
            discount_percent=discount,
            bank_details=request.form.get('bank_details'), 
            upi_id=request.form.get('upi_id')
        )
        new_dist.set_password(password)
        
        db.session.add(new_dist)
        db.session.commit()
        flash('Distributor added successfully!', 'success')
        
    except Exception as e: 
        print(f"ADD DIST ERROR: {e}") # Check Render Logs
        flash(f'Database Error: {str(e)}', 'danger')
        
    return redirect(url_for('dashboard'))

# --- UPDATE THIS ROUTE ---
@app.route('/admin/edit_distributor/<int:id>', methods=['POST'])
@login_required
def edit_distributor(id):
    dist = Distributor.query.get_or_404(id)
    
    try:
        # Basic Info
        dist.name = request.form.get('name')
        dist.email = request.form.get('email')
        dist.phone = request.form.get('phone')
        dist.bank_details = request.form.get('bank_details')
        dist.upi_id = request.form.get('upi_id')
        
        # Update Password only if provided
        new_pass = request.form.get('password')
        if new_pass and new_pass.strip():
            dist.set_password(new_pass.strip())

        # --- PAYMENT LOGIC ---
        
        # Option A: Add to existing (Normal Flow)
        payment_add = request.form.get('add_payment')
        if payment_add and payment_add.strip():
            dist.commission_paid += float(payment_add)
            
        # Option B: Manual Correction (Edit the total directly)
        manual_total = request.form.get('manual_paid_total')
        if manual_total and manual_total.strip():
            dist.commission_paid = float(manual_total)

        db.session.commit()
        flash('Distributor updated successfully', 'success')
        
    except Exception as e:
        flash(f'Error updating: {str(e)}', 'danger')
        
    return redirect(url_for('dashboard'))



@app.route('/admin/delete_distributor/<int:id>', methods=['POST'])
@login_required
def delete_distributor(id):
    dist = Distributor.query.get_or_404(id)
    db.session.delete(dist)
    db.session.commit()
    flash('Distributor deleted', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_license/<int:id>', methods=['POST'])
@login_required
def delete_license(id):
    db.session.delete(License.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_license/<int:id>', methods=['POST'])
@login_required
def edit_license(id):
    lic = License.query.get_or_404(id)
    lic.is_used = True if request.form.get('is_used') == 'on' else False
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USERNAME and request.form.get('password') == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/admin/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(FRONTEND_URL)

# --- DISTRIBUTOR API ---
@app.route('/api/distributor/login', methods=['POST'])
def api_distributor_login():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get('email')).first()
    if dist and dist.check_password(data.get('password')):
        dist.api_token = secrets.token_hex(16)
        db.session.commit()
        return jsonify({'success': True, 'token': dist.api_token})
    return jsonify({'success': False})

@app.route('/api/distributor/data', methods=['GET'])
def api_get_distributor_data():
    token = request.headers.get('Authorization').split(" ")[1] if request.headers.get('Authorization') else None
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({'error': 'Invalid Token'}), 401
    
    sales = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc()).all()
    total_earned = sum(l.amount_paid for l in sales) * 0.20
    
    sales_data = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key} for s in sales]
    
    return jsonify({
        'name': dist.name, 'code': dist.code, 'discount': dist.discount_percent,
        'total_sales': len(sales), 
        'commission_earned': total_earned,
        'commission_paid': dist.commission_paid,
        'balance_due': total_earned - dist.commission_paid,
        'sales_history': sales_data,
        'backend_url': request.host_url
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    dist = Distributor.query.filter_by(email=request.json.get('email')).first()
    if not dist: return jsonify({'success': False, 'message': 'Email not found'})
    dist.reset_token = secrets.token_urlsafe(32)
    db.session.commit()
    print(f"RESET LINK: {url_for('reset_password_page', token=dist.reset_token, _external=True)}")
    return jsonify({'success': True, 'message': 'Reset link sent/generated'})

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    dist = Distributor.query.filter_by(reset_token=token).first()
    if request.method == 'POST':
        dist.set_password(request.form.get('password'))
        dist.reset_token = None
        db.session.commit()
        return "Password Updated"
    return render_template('reset_password.html', token=token)

# --- RESET DB ---
@app.route('/reset-db-now')
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Create Demo Distributor to verify functionality
        if not Distributor.query.first():
            demo = Distributor(code="DEMO", name="Demo User", phone="999", email="demo@gmail.com", discount_percent=10)
            demo.set_password("demo123")
            db.session.add(demo)
            db.session.commit()
    return "DB Reset. New columns added."

if __name__ == '__main__':
    app.run(debug=True)
