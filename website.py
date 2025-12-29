import os
import random
import string
import secrets
import csv
import io
import requests
import razorpay
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash,
    make_response, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ZARQEEN_ALIF_SECURE_99")

# RENDER ENVIRONMENT VARIABLES
BACKEND_URL = os.environ.get("BACKEND_URL")
DOWNLOAD_LINK = os.environ.get("DOWNLOAD_LINK")
VERSION = os.environ.get("VERSION", "1.2.0")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") 
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# CORS and Session Security
CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

# Database
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- MODELS ---
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    special_bonus_percent = db.Column(db.Integer, default=0)

class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True) # New: Enable/Disable Toggle
    discount_percent = db.Column(db.Integer, default=10)
    commission_paid = db.Column(db.Float, default=0.0)
    api_token = db.Column(db.String(100))
    otp_code = db.Column(db.String(10)); otp_expiry = db.Column(db.DateTime)
    
    bank_name = db.Column(db.String(100)); account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50)); ifsc_code = db.Column(db.String(20)); upi_id = db.Column(db.String(100))
    
    licenses = db.relationship('License', backref='distributor', lazy=True)
    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(60), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100))
    amount_paid = db.Column(db.Float, default=0.0)
    commission_earned = db.Column(db.Float, default=0.0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used_at = db.Column(db.DateTime); software_version = db.Column(db.String(20))
    distributor_id = db.Column(db.Integer, db.ForeignKey('distributor.id'))
    
    @property
    def expiry_date(self):
        if not self.used_at: return None
        return self.used_at + timedelta(days=(365 if self.plan_type == 'basic' else 1095))

# --- DECORATORS & HELPERS ---
def admin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get('admin_logged_in'): return redirect("https://zarqeen.in")
        return f(*args, **kwargs)
    return wrap

def send_brevo_email(to_email, subject, html):
    if not BREVO_API_KEY: return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"api-key": BREVO_API_KEY, "content-type": "application/json"}
    payload = {"sender": {"name": "Zarqeen", "email": "zarqeensoftware@gmail.com"}, "to": [{"email": to_email}], "subject": subject, "htmlContent": html}
    try: requests.post(url, json=payload, timeout=5); return True
    except: return False

def generate_key(plan_type, dist_code=None):
    prefix = "ALBA" if plan_type == 'basic' else "ALPR"
    code = dist_code.upper() if dist_code else "ALIF"
    rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    key = f"{prefix}-{code}-{rand[:4]}-{rand[4:]}"
    return key if not License.query.filter_by(license_key=key).first() else generate_key(plan_type, dist_code)

# --- PUBLIC ROUTES & HANDSHAKE ---
@app.route('/')
def home(): return redirect("https://zarqeen.in")

@app.route('/api/v1/config')
def get_public_config():
    """Provides public Render env vars to the frontend dynamically."""
    return jsonify({
        "BACKEND_URL": BACKEND_URL,
        "DOWNLOAD_LINK": DOWNLOAD_LINK,
        "VERSION": VERSION,
        "RAZORPAY_KEY_ID": RAZORPAY_KEY_ID
    })

@app.route('/api/get-config')
def get_razor_config(): return jsonify({'key_id': RAZORPAY_KEY_ID})

@app.route("/admin/login", methods=["POST"])
def admin_login_api():
    """Secure Admin login returning JSON (Shields backend URL)."""
    data = request.json or {}
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
    return jsonify({'success': False, 'message': 'Invalid Admin Credentials'}), 401

# --- ADMIN DASHBOARD ROUTES ---
@app.route("/admin/dashboard")
@admin_login_required
def admin_dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    settings = db.session.get(Settings, 1) or Settings(id=1)
    if not db.session.get(Settings, 1): db.session.add(settings); db.session.commit()
    
    dist_list = []
    for d in distributors:
        earned = sum(l.commission_earned for l in d.licenses)
        dist_list.append({"obj": d, "earned": round(earned, 2), "balance": round(earned - d.commission_paid, 2)})
    
    return render_template("admin_dashboard.html", licenses=licenses, distributors=dist_list, settings=settings)

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@admin_login_required
def edit_distributor(id):
    d = db.session.get(Distributor, id)
    if request.form.get("name"): d.name = request.form.get("name")
    if request.form.get("email"): d.email = request.form.get("email")
    if "is_active" in request.form: d.is_active = (request.form.get("is_active") == "1")
    if request.form.get("manual_paid_total"): d.commission_paid = float(request.form.get("manual_paid_total"))
    if request.form.get("upi_id"): d.upi_id = request.form.get("upi_id")
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@admin_login_required
def delete_distributor(id):
    db.session.delete(db.session.get(Distributor, id))
    db.session.commit(); return redirect(url_for('admin_dashboard'))

@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@admin_login_required
def edit_license(id):
    l = db.session.get(License, id)
    l.is_used = (request.form.get("status") == "used")
    db.session.commit(); return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@admin_login_required
def delete_license(id):
    db.session.delete(db.session.get(License, id))
    db.session.commit(); return redirect(url_for('admin_dashboard'))

@app.route("/admin/logout")
def admin_logout(): session.pop("admin_logged_in", None); return redirect("https://zarqeen.in")

# --- DISTRIBUTOR DASHBOARD API ---
@app.route('/api/distributor/data', methods=['GET'])
def get_dist_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist or not dist.is_active: return jsonify({'error': 'Unauthorized'}), 401

    earned = sum(l.commission_earned for l in dist.licenses)
    sd = [{
        'date': s.created_at.strftime('%Y-%m-%d'), 
        'plan': s.plan_type.upper(), 
        'amount': s.amount_paid, 
        'status': 'USED' if s.is_used else 'PENDING', 
        'key': s.license_key
    } for s in dist.licenses]

    return jsonify({
        "name": dist.name, "code": dist.code,
        "earned": round(earned, 2), "paid": round(dist.commission_paid, 2), "balance": round(earned - dist.commission_paid, 2),
        "history": sd
    })

# --- CORE BUSINESS LOGIC (OTP, PAYMENTS, VALIDATE) ---
@app.route('/api/distributor/register', methods=['POST'])
def register_dist():
    d = request.json; email = d.get('email', '').strip()
    if Distributor.query.filter_by(email=email).first(): return jsonify({'success': False, 'message': 'Already registered'})
    otp = str(random.randint(100000, 999999))
    while True:
        c = ''.join(random.choices(string.ascii_uppercase, k=4))
        if not Distributor.query.filter_by(code=c).first(): break
    new_d = Distributor(code=c, name=d.get('name'), phone=d.get('phone'), email=email, otp_code=otp, otp_expiry=datetime.now(timezone.utc)+timedelta(minutes=10))
    new_d.set_password(d.get('password')); db.session.add(new_d); db.session.commit()
    send_brevo_email(email, "Verification Code", f"Your OTP: {otp}")
    return jsonify({'success': True, 'message': 'OTP Sent'})

@app.route('/api/distributor/verify-registration', methods=['POST'])
def verify_reg():
    d = request.json; dist = Distributor.query.filter_by(email=d.get('email')).first()
    if dist and dist.otp_code == d.get('otp'):
        dist.is_active = True; db.session.commit(); return jsonify({'success': True, 'code': dist.code})
    return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/api/distributor/login', methods=['POST'])
def dist_login():
    d = request.json; dist = Distributor.query.filter_by(email=d.get('email')).first()
    if dist and dist.check_password(d.get('password')) and dist.is_active:
        dist.api_token = secrets.token_hex(16); db.session.commit(); return jsonify({'success': True, 'token': dist.api_token})
    return jsonify({'success': False, 'message': 'Login Failed or Account Disabled'})

@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.json; amount = 29900 if data.get('plan') == 'basic' else 59900
    code = data.get('distributor_code', '').strip().upper()
    dist = Distributor.query.filter_by(code=code, is_active=True).first()
    if dist: amount -= int(amount * (dist.discount_percent / 100))
    order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'notes': {'plan': data.get('plan'), 'dist_id': dist.id if dist else 'None'}})
    return jsonify(order)

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    d = request.json
    try:
        razorpay_client.utility.verify_payment_signature(d)
        order = razorpay_client.order.fetch(d['razorpay_order_id'])
        plan = order['notes']['plan']; dist_id = order['notes']['dist_id']
        dist = db.session.get(Distributor, int(dist_id)) if dist_id != 'None' else None
        
        # Calculate commission (approx 25% for partners)
        comm = (order['amount'] / 100) * 0.25 if dist else 0.0
        new_key = generate_key(plan, dist.code if dist else None)
        lic = License(license_key=new_key, plan_type=plan, amount_paid=order['amount']/100, commission_earned=comm, distributor_id=dist.id if dist else None)
        db.session.add(lic); db.session.commit()
        return jsonify({'success': True, 'license_key': new_key})
    except: return jsonify({'success': False})

@app.route('/download/license/<key>')
def download_license(key):
    return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    d = request.json; lic = License.query.filter_by(license_key=d.get('license_key', '').strip()).first()
    if not lic: return jsonify({'valid': False, 'message': 'Invalid Key'}), 404
    lic.software_version = d.get('version', '1.0.0'); lic.last_login_date = datetime.now(timezone.utc)
    if not lic.is_used: lic.is_used = True; lic.used_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'valid': True, 'plan': lic.plan_type, 'dist_phone': lic.distributor.phone if lic.distributor else "N/A"})

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=False)
