import os
import random
import string
import secrets
import csv
import io
import razorpay
from datetime import datetime, timedelta
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

# Database
raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Credentials
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# --- MAIL CONFIGURATION (SAFE) ---
# Defaults to Gmail if not specified. Change MAIL_SERVER env var for Brevo.
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Zarqeen Support', os.environ.get('MAIL_USERNAME', 'noreply@zarqeen.in'))

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
    
    bank_name = db.Column(db.String(100), nullable=True)
    account_holder = db.Column(db.String(100), nullable=True)
    account_number = db.Column(db.String(50), nullable=True)
    ifsc_code = db.Column(db.String(20), nullable=True)
    upi_id = db.Column(db.String(100), nullable=True)
    
    commission_paid = db.Column(db.Float, default=0.0)      
    api_token = db.Column(db.String(100), nullable=True)
    
    otp_code = db.Column(db.String(10), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
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
    try: db.create_all()
    except: pass

# --- HELPERS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_unique_key(plan_type, dist_code=None):
    plan_str = "BA" if plan_type == 'basic' else "PR"
    d_part = dist_code.upper().strip()[:4] if dist_code else "ALIF"
    if len(d_part) < 4: d_part = d_part.ljust(4, 'X') 
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    full_key = f"ZQ{plan_str}-{d_part}-{part1}-{part2}"
    if License.query.filter_by(license_key=full_key).first(): return generate_unique_key(plan_type, dist_code)
    return full_key

def safe_float(val):
    try: return float(val) if val else 0.0
    except: return 0.0

# --- ROUTES ---
@app.route('/')
def home(): return redirect(FRONTEND_URL)

@app.route('/api/get-config', methods=['GET'])
def get_config(): return jsonify({'key_id': RAZORPAY_KEY_ID})

@app.route('/api/check_distributor', methods=['POST'])
def check_distributor():
    try:
        data = request.json
        code = data.get('code', '').strip().upper()
        dist = Distributor.query.filter_by(code=code).first()
        if dist: return jsonify({'valid': True, 'discount': dist.discount_percent, 'name': dist.name})
        return jsonify({'valid': False})
    except Exception as e: return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        plan = data.get('plan')
        code = data.get('distributor_code', '').strip().upper() if data.get('distributor_code') else ""
        
        base_amount = 29900 if plan == 'basic' else 59900
        final_amount = base_amount
        dist_id_str = "None"
        
        if code:
            try:
                dist = Distributor.query.filter_by(code=code).first()
                if dist:
                    discount_amount = (base_amount * dist.discount_percent) / 100
                    final_amount = int(base_amount - discount_amount)
                    dist_id_str = str(dist.id)
            except: pass
        
        order = razorpay_client.order.create({
            'amount': final_amount, 'currency': 'INR', 'payment_capture': '1',
            'notes': {'plan': str(plan), 'distributor_id': dist_id_str}
        })
        return jsonify(order)
    except Exception as e: 
        print(f"Order Error: {e}")
        return jsonify({'error': str(e)}), 500

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
        dist_obj = None
        if dist_id_val and dist_id_val != "None":
            try: dist_obj = Distributor.query.get(int(dist_id_val))
            except: pass
        
        new_key = generate_unique_key(data.get('plan_type'), dist_obj.code if dist_obj else None)
        new_license = License(
            license_key=new_key, plan_type=data.get('plan_type'), payment_id=data['razorpay_payment_id'],
            amount_paid=order_info['amount'] / 100, distributor_id=dist_obj.id if dist_obj else None
        )
        db.session.add(new_license)
        db.session.commit()
        return jsonify({'success': True, 'license_key': new_key})
    except Exception as e: return jsonify({'success': False, 'message': str(e)})

@app.route('/download/license/<key>')
def download_license_file(key):
    return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json
    key_input = data.get('license_key', '').strip()
    lic = License.query.filter_by(license_key=key_input).first()
    if lic:
        if lic.is_used: return jsonify({'valid': False, 'message': 'License already used.'})
        lic.is_used = True
        lic.used_at = datetime.utcnow()
        db.session.commit()
        
        support_name = lic.distributor.name if lic.distributor else "Zarqeen Official"
        support_contact = lic.distributor.phone if lic.distributor else "zarqeensoftware@gmail.com"
        duration = 365 if lic.plan_type == 'basic' else 1095
        return jsonify({'valid': True, 'plan': lic.plan_type, 'duration_days': duration, 'support_info': {'name': support_name, 'contact': support_contact}})
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

# --- ADMIN PANEL ---
@app.route('/admin/dashboard')
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    dist_data = []
    for d in distributors:
        paid = safe_float(d.commission_paid)
        earned = sum(safe_float(l.amount_paid) for l in d.licenses) * 0.20
        balance = earned - paid
        dist_data.append({'obj': d, 'earned': earned, 'balance': balance})
    return render_template('dashboard.html', licenses=licenses, distributors=dist_data)

@app.route('/admin/add_distributor', methods=['POST'])
@login_required
def add_distributor():
    try:
        code = request.form.get('code', '').strip().upper()
        email = request.form.get('email', '').strip()
        if not code or not email:
            flash('Required fields missing', 'danger'); return redirect(url_for('dashboard'))
        if Distributor.query.filter((Distributor.code==code) | (Distributor.email==email)).first():
            flash('Code/Email exists', 'danger'); return redirect(url_for('dashboard'))
        
        new_dist = Distributor(
            code=code, name=request.form.get('name', '').strip(), phone=request.form.get('phone', '').strip(),
            email=email, discount_percent=int(request.form.get('discount', 10)),
            bank_name=request.form.get('bank_name', '').strip(), account_holder=request.form.get('account_holder', '').strip(),
            account_number=request.form.get('account_number', '').strip(), ifsc_code=request.form.get('ifsc_code', '').strip(),
            upi_id=request.form.get('upi_id', '').strip()
        )
        new_dist.set_password(request.form.get('password', '123456'))
        db.session.add(new_dist)
        db.session.commit()
        flash('Added', 'success')
    except Exception as e: flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_distributor/<int:id>', methods=['POST'])
@login_required
def edit_distributor(id):
    dist = Distributor.query.get_or_404(id)
    try:
        dist.name = request.form.get('name'); dist.email = request.form.get('email'); dist.phone = request.form.get('phone')
        if request.form.get('discount'): dist.discount_percent = int(request.form.get('discount'))
        dist.bank_name = request.form.get('bank_name'); dist.account_holder = request.form.get('account_holder')
        dist.account_number = request.form.get('account_number'); dist.ifsc_code = request.form.get('ifsc_code'); dist.upi_id = request.form.get('upi_id')
        
        add_pay = request.form.get('add_payment'); manual_pay = request.form.get('manual_paid_total')
        if add_pay and safe_float(add_pay) > 0: dist.commission_paid = safe_float(dist.commission_paid) + safe_float(add_pay)
        elif manual_pay and manual_pay.strip(): dist.commission_paid = safe_float(manual_pay)
            
        if request.form.get('password'): dist.set_password(request.form.get('password'))
        db.session.commit()
        flash('Updated', 'success')
    except Exception as e: flash(str(e), 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_distributor/<int:id>', methods=['POST'])
@login_required
def delete_distributor(id):
    dist = Distributor.query.get_or_404(id)
    for l in License.query.filter_by(distributor_id=id).all(): l.distributor_id = None
    db.session.delete(dist)
    db.session.commit()
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
    status = request.form.get('status')
    if status == 'used': lic.is_used = True
    elif status == 'active': lic.is_used = False
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/export/<type>')
@login_required
def export_data(type):
    si = io.StringIO(); cw = csv.writer(si)
    if type == 'licenses':
        cw.writerow(['Date', 'Key', 'Plan', 'Amount', 'Distributor', 'Status'])
        for r in License.query.all():
            d_name = r.distributor.name if r.distributor else 'Direct'
            cw.writerow([r.created_at, r.license_key, r.plan_type, r.amount_paid, d_name, r.is_used])
    elif type == 'distributors':
        cw.writerow(['Name', 'Code', 'Email', 'Phone', 'Bank', 'Acct No', 'IFSC', 'UPI', 'Total Earned', 'Paid', 'Balance'])
        for r in Distributor.query.all():
            total_earned = sum(safe_float(l.amount_paid) for l in r.licenses) * 0.20
            balance = total_earned - safe_float(r.commission_paid)
            cw.writerow([r.name, r.code, r.email, r.phone, r.bank_name, r.account_number, r.ifsc_code, r.upi_id, total_earned, r.commission_paid, balance])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=export_{type}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

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
    
    page = request.args.get('page', 1, type=int)
    query = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc())
    pagination = query.paginate(page=page, per_page=10, error_out=False)
    
    total_earned = sum(safe_float(l.amount_paid) for l in query.all()) * 0.20
    sales_data = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key} for s in pagination.items]
    
    return jsonify({
        'name': dist.name, 'code': dist.code, 'discount': dist.discount_percent, 'email': dist.email, 'phone': dist.phone,
        'total_sales': query.count(), 'commission_earned': total_earned,
        'commission_paid': safe_float(dist.commission_paid), 'balance_due': total_earned - safe_float(dist.commission_paid),
        'sales_history': sales_data, 'backend_url': request.host_url,
        'bank_info': {'bank_name': dist.bank_name, 'account_holder': dist.account_holder, 'account_number': dist.account_number, 'ifsc': dist.ifsc_code, 'upi': dist.upi_id},
        'pagination': {'total_pages': pagination.pages, 'has_next': pagination.has_next, 'has_prev': pagination.has_prev}
    })

# --- OTP FLOW (CRASH PROOF) ---
@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')
    dist = Distributor.query.filter_by(email=email).first()
    if not dist: return jsonify({'success': False, 'message': 'Email not registered'})
    
    dist.otp_code = str(random.randint(100000, 999999))
    dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    
    # 1. LOG OTP (Fallback)
    print(f"\n >>> DEBUG OTP for {email}: {dist.otp_code} <<<\n")
    
    # 2. CHECK CREDENTIALS
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        return jsonify({
            'success': True, 
            'message': 'OTP generated. Check server logs (Email config missing).'
        })

    # 3. ATTEMPT SENDING (Silent Fail if OOM)
    try:
        msg = Message("Zarqeen Verification Code", recipients=[email])
        msg.body = f"Your verification code is: {dist.otp_code}\n\nThis code expires in 10 minutes."
        mail.send(msg)
        return jsonify({'success': True, 'message': 'OTP sent to email'})
    except Exception as e:
        print(f"Mail failed: {e}")
        # Return success so user can use the Log OTP
        return jsonify({'success': True, 'message': 'OTP sent (Check logs if email not received)'})

@app.route('/api/reset-with-otp', methods=['POST'])
def reset_with_otp():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get('email')).first()
    if not dist: return jsonify({'success': False, 'message': 'User not found'})
    
    if not dist.otp_code or not dist.otp_expiry:
        return jsonify({'success': False, 'message': 'No OTP request found'})
        
    if datetime.utcnow() > dist.otp_expiry:
        return jsonify({'success': False, 'message': 'OTP expired'})
        
    if str(dist.otp_code) == str(data.get('otp')):
        dist.set_password(data.get('new_password'))
        dist.otp_code = None
        dist.otp_expiry = None
        db.session.commit()
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    
    return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/reset-db-now')
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        if not Distributor.query.first():
            d = Distributor(code="DEMO", name="Demo", phone="999", email="demo@gmail.com", discount_percent=10)
            d.set_password("demo123")
            db.session.add(d)
            db.session.commit()
    return "DB Reset"

if __name__ == '__main__':
    app.run(debug=True)
