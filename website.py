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

# Fetching variables from Render Environment
app.secret_key = os.environ.get("SECRET_KEY", "ZARQEEN_SECURE_7788")
BACKEND_URL = os.environ.get("BACKEND_URL", "").rstrip('/')
DOWNLOAD_LINK = os.environ.get("DOWNLOAD_LINK", "https://zarqeen.in")
VERSION = os.environ.get("VERSION", "1.2.0")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Security for Cross-Domain sessions
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

# Robust CORS for your domain
CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)

# Database
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Razorpay
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID or "", RAZORPAY_KEY_SECRET or ""))

# --- MODELS ---
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    special_bonus_percent = db.Column(db.Integer, default=0)

class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    commission_paid = db.Column(db.Float, default=0.0)
    discount_percent = db.Column(db.Integer, default=10)
    api_token = db.Column(db.String(100))
    otp_code = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime)
    upi_id = db.Column(db.String(100))
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
    used_at = db.Column(db.DateTime)
    software_version = db.Column(db.String(20))
    distributor_id = db.Column(db.Integer, db.ForeignKey('distributor.id'))
    
    @property
    def expiry_date(self):
        if not self.used_at: return None
        return self.used_at + timedelta(days=(365 if self.plan_type == 'basic' else 1095))

# --- DATABASE AUTO-INIT ---
with app.app_context():
    db.create_all()
    if not db.session.get(Settings, 1):
        db.session.add(Settings(id=1))
        db.session.commit()

# --- HELPERS ---
def admin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get('admin_logged_in'): return redirect("https://zarqeen.in")
        return f(*args, **kwargs)
    return wrap

def generate_key(plan_type, dist_code=None):
    prefix = "ALBA" if plan_type == 'basic' else "ALPR"
    code = dist_code.upper() if dist_code else "ALIF"
    rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    key = f"{prefix}-{code}-{rand[:4]}-{rand[4:]}"
    return key if not License.query.filter_by(license_key=key).first() else generate_key(plan_type, dist_code)

# --- ROUTES ---

@app.route('/')
def index():
    return f"Zarqeen Security Server {VERSION} is Online.", 200

@app.route('/api/v1/config')
def get_public_config():
    return jsonify({
        "BACKEND_URL": BACKEND_URL or request.host_url.rstrip('/'),
        "DOWNLOAD_LINK": DOWNLOAD_LINK,
        "VERSION": VERSION,
        "RAZORPAY_KEY_ID": RAZORPAY_KEY_ID
    })

@app.route("/admin/login", methods=["POST"])
def admin_login_api():
    data = request.json or {}
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
    return jsonify({'success': False, 'message': 'Invalid Admin Credentials'}), 401

@app.route("/admin/dashboard")
@admin_login_required
def admin_dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    settings = db.session.get(Settings, 1)
    dist_list = []
    for d in distributors:
        earned = sum(l.commission_earned for l in d.licenses)
        dist_list.append({"obj": d, "earned": round(earned, 2), "balance": round(earned - d.commission_paid, 2)})
    return render_template("admin_dashboard.html", licenses=licenses, distributors=dist_list, settings=settings)

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@admin_login_required
def edit_distributor(id):
    d = db.session.get(Distributor, id)
    if not d: return redirect(url_for('admin_dashboard'))
    if request.form.get("name"): d.name = request.form.get("name")
    if "is_active" in request.form: d.is_active = (request.form.get("is_active") == "1")
    if request.form.get("manual_paid_total"): d.commission_paid = float(request.form.get("manual_paid_total"))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@admin_login_required
def delete_distributor(id):
    d = db.session.get(Distributor, id)
    if d:
        db.session.delete(d)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@admin_login_required
def edit_license(id):
    l = db.session.get(License, id)
    if l:
        l.is_used = (request.form.get("status") == "used")
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@admin_login_required
def delete_license(id):
    l = db.session.get(License, id)
    if l:
        db.session.delete(l)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/api/distributor/data', methods=['GET'])
def get_dist_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist or not dist.is_active: return jsonify({'error': 'Unauthorized'}), 401
    earned = sum(l.commission_earned for l in dist.licenses)
    sd = [{'date': l.created_at.strftime('%d-%b-%Y'), 'plan': l.plan_type.upper(), 'amount': l.amount_paid, 'status': 'USED' if l.is_used else 'PENDING', 'key': l.license_key} for l in dist.licenses]
    return jsonify({"name": dist.name, "code": dist.code, "earned": round(earned, 2), "paid": round(dist.commission_paid, 2), "balance": round(earned - dist.commission_paid, 2), "history": sd})

@app.route('/download/license/<key>')
def download_license_file(key):
    return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    d = request.json or {}
    lic = License.query.filter_by(license_key=d.get('license_key', '').strip()).first()
    if not lic: return jsonify({'valid': False, 'message': 'Invalid Key'}), 404
    lic.software_version = d.get('version', '1.0.0')
    lic.last_login_date = datetime.now(timezone.utc)
    if not lic.is_used:
        lic.is_used = True
        lic.used_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'valid': True, 'plan': lic.plan_type, 'dist_phone': lic.distributor.phone if lic.distributor else "N/A"})

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect("https://zarqeen.in")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
