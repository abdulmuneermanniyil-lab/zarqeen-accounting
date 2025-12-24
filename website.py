import os
import random
import string
import secrets
import csv
import io
import requests
import razorpay
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash,
    make_response, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# 1. APP CONFIGURATION
# -------------------------------------------------
app = Flask(__name__)
# Security: Load secret from ENV, fallback to random if missing (forces session invalidation on restart if not set)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
FRONTEND_URL = "https://zarqeen.in"

# Cookie Security (Cross-Domain)
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None 
)

# CORS (Allow Frontend)
CORS(
    app,
    resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}},
    supports_credentials=True
)

# Database
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Optimization to prevent "SSL SYSCALL" errors
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 2,
    "max_overflow": 1
}

db = SQLAlchemy(app)

# -------------------------------------------------
# 2. KEYS & CREDENTIALS (SECURE)
# -------------------------------------------------
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") 

# SECURE: No default values. Must be set in Render Environment Variables.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Constants
LEVELS = {
    1: {'name': 'Bronze', 'discount': 10, 'commission': 15, 'target': 0},
    2: {'name': 'Silver', 'discount': 15, 'commission': 25, 'target': 5},
    3: {'name': 'Gold',   'discount': 20, 'commission': 40, 'target': 20}
}

# -------------------------------------------------
# 3. DATABASE MODELS
# -------------------------------------------------
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    special_bonus_percent = db.Column(db.Integer, default=0)
    special_message = db.Column(db.String(100), default="")

class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    discount_percent = db.Column(db.Integer, default=10)
    bank_name = db.Column(db.String(100)); account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50)); ifsc_code = db.Column(db.String(20)); upi_id = db.Column(db.String(100))
    commission_paid = db.Column(db.Float, default=0.0); api_token = db.Column(db.String(100))
    otp_code = db.Column(db.String(10)); otp_expiry = db.Column(db.DateTime); reset_token = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    level = db.Column(db.Integer, default=1); last_level_check = db.Column(db.DateTime, default=datetime.utcnow)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime); last_login_date = db.Column(db.DateTime); software_version = db.Column(db.String(20))
    distributor_id = db.Column(db.Integer, db.ForeignKey('distributor.id'))
    @property
    def expiry_date(self):
        if not self.used_at: return None
        days = 365 if self.plan_type == 'basic' else 1095
        return self.used_at + timedelta(days=days)

# -------------------------------------------------
# 4. HELPERS
# -------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get('admin_logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

def safe_float(v):
    try: return float(v)
    except: return 0.0

def generate_unique_key(plan_type, dist_code=None):
    p = "BA" if plan_type == 'basic' else "PR"
    d = dist_code.upper().strip()[:4] if dist_code else "ALIF"
    d = d.ljust(4, 'X')
    r1 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    r2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    key = f"ZQ{p}-{d}-{r1}-{r2}"
    if License.query.filter_by(license_key=key).first(): return generate_unique_key(plan_type, dist_code)
    return key

def send_brevo_email(to_email, subject, html_content):
    if not BREVO_API_KEY: print(">>> BREVO KEY MISSING"); return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"api-key": BREVO_API_KEY, "content-type": "application/json"}
    payload = {"sender": {"name": "Zarqeen Support", "email": "zarqeensoftware@gmail.com"}, "to": [{"email": to_email}], "subject": subject, "htmlContent": html_content}
    try: requests.post(url, json=payload, headers=headers, timeout=5); return True
    except: return False

def check_level_update(dist):
    now = datetime.utcnow()
    if dist.last_level_check and dist.last_level_check.month == now.month and dist.last_level_check.year == now.year: return
    first = now.replace(day=1)
    last_month_end = first - timedelta(days=1)
    last_month_start = last_month_end.replace(day=1)
    count = License.query.filter(License.distributor_id==dist.id, License.created_at >= last_month_start, License.created_at <= last_month_end).count()
    current = dist.level; new_lvl = current
    if current < 3 and count >= LEVELS[current+1]['target']: new_lvl += 1
    elif current > 1 and count < LEVELS[current]['target']: new_lvl -= 1
    dist.level = new_lvl; dist.last_level_check = now; db.session.commit()

# -------------------------------------------------
# 5. ROUTES
# -------------------------------------------------
@app.route('/')
def home(): return redirect(FRONTEND_URL)

@app.route('/api/get-config')
def get_config(): return jsonify({'key_id': RAZORPAY_KEY_ID})

@app.route('/api/check_distributor', methods=['POST'])
def check_distributor():
    try:
        code = request.json.get('code', '').strip().upper()
        dist = Distributor.query.filter_by(code=code).first()
        if dist and dist.is_verified:
            disc = LEVELS[dist.level]['discount']
            return jsonify({'valid': True, 'discount': disc, 'name': dist.name})
        return jsonify({'valid': False})
    except: return jsonify({'valid': False}), 500

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json; code = data.get('distributor_code', '').strip().upper()
        base_amount = 29900 if data.get('plan') == 'basic' else 59900
        final_amount = base_amount; dist_id_str = "None"
        if code:
            dist = Distributor.query.filter_by(code=code).first()
            if dist and dist.is_verified:
                disc_pct = LEVELS[dist.level]['discount']
                final_amount = int(base_amount - ((base_amount * disc_pct) / 100))
                dist_id_str = str(dist.id)
        order = razorpay_client.order.create({'amount': final_amount, 'currency': 'INR', 'payment_capture': '1', 'notes': {'plan': str(data.get('plan')), 'distributor_id': dist_id_str}})
        return jsonify(order)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json
    try:
        razorpay_client.utility.verify_payment_signature({'razorpay_order_id': data['razorpay_order_id'], 'razorpay_payment_id': data['razorpay_payment_id'], 'razorpay_signature': data['razorpay_signature']})
        order = razorpay_client.order.fetch(data['razorpay_order_id'])
        dist_id = order['notes'].get('distributor_id')
        dist_obj = Distributor.query.get(int(dist_id)) if dist_id and dist_id != "None" else None
        
        commission = 0.0
        if dist_obj:
            mrp = 299.0 if data.get('plan_type') == 'basic' else 599.0
            settings = Settings.query.first()
            bonus = settings.special_bonus_percent if settings else 0
            total_pct = LEVELS[dist_obj.level]['commission'] + bonus
            commission = (mrp * total_pct) / 100

        new_key = generate_unique_key(data.get('plan_type'), dist_obj.code if dist_obj else None)
        new_lic = License(license_key=new_key, plan_type=data.get('plan_type'), payment_id=data['razorpay_payment_id'], amount_paid=order['amount']/100, commission_earned=commission, distributor_id=dist_obj.id if dist_obj else None)
        db.session.add(new_lic); db.session.commit()
        return jsonify({'success': True, 'license_key': new_key})
    except Exception as e: return jsonify({'success': False, 'message': str(e)})

@app.route('/download/license/<key>')
def download_license_file(key): return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json; lic = License.query.filter_by(license_key=data.get('license_key', '').strip()).first()
    if lic:
        lic.software_version = data.get('version', 'Unknown'); lic.last_login_date = datetime.utcnow()
        if lic.is_used: db.session.commit(); return jsonify({'valid': False, 'message': 'License used.'})
        lic.is_used = True; lic.used_at = datetime.utcnow(); db.session.commit()
        dur = 365 if lic.plan_type == 'basic' else 1095
        return jsonify({'valid': True, 'plan': lic.plan_type, 'duration_days': dur, 'support_info': {'name': lic.distributor.name if lic.distributor else "Zarqeen", 'contact': lic.distributor.phone if lic.distributor else "zarqeensoftware@gmail.com"}})
    return jsonify({'valid': False, 'message': 'Invalid Key'})

# --- ADMIN ROUTES ---
@app.route("/admin/dashboard")
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    settings = Settings.query.first()
    if not settings: settings = Settings(); db.session.add(settings); db.session.commit()
    
    dist_data = []
    for d in distributors:
        earned = sum(safe_float(l.commission_earned) for l in d.licenses)
        dist_data.append({"obj": d, "earned": earned, "balance": earned - safe_float(d.commission_paid), "level_name": LEVELS.get(d.level, {'name':'Bronze'})['name']})
    return render_template("dashboard.html", licenses=licenses, distributors=dist_data, settings=settings)

@app.route("/admin/update_settings", methods=["POST"])
@login_required
def update_settings():
    settings = Settings.query.first(); settings.special_bonus_percent = int(request.form.get('bonus', 0)); settings.special_message = request.form.get('message', ''); db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/admin/add_distributor", methods=["POST"])
@login_required
def add_distributor():
    try:
        code = request.form.get("code", "").strip().upper(); email = request.form.get("email", "").strip()
        if not code or not email: return redirect(url_for("dashboard"))
        if Distributor.query.filter((Distributor.code==code)|(Distributor.email==email)).first(): return redirect(url_for("dashboard"))
        new_dist = Distributor(code=code, name=request.form.get("name"), phone=request.form.get("phone"), email=email, discount_percent=10, is_verified=True, level=1)
        new_dist.set_password(request.form.get("password")); db.session.add(new_dist); db.session.commit()
    except: pass
    return redirect(url_for("dashboard"))

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@login_required
def edit_distributor(id):
    dist = Distributor.query.get_or_404(id)
    dist.name = request.form.get("name"); dist.email = request.form.get("email"); dist.phone = request.form.get("phone")
    dist.bank_name = request.form.get("bank_name"); dist.account_holder = request.form.get("account_holder"); dist.account_number = request.form.get("account_number"); dist.ifsc_code = request.form.get("ifsc_code"); dist.upi_id = request.form.get("upi_id")
    add_pay = request.form.get("add_payment"); man_pay = request.form.get("manual_paid_total")
    if add_pay and safe_float(add_pay) > 0: dist.commission_paid += safe_float(add_pay)
    elif man_pay and man_pay.strip(): dist.commission_paid = safe_float(man_pay)
    if request.form.get("password"): dist.set_password(request.form.get("password"))
    db.session.commit(); return redirect(url_for("dashboard"))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@login_required
def delete_distributor(id): db.session.delete(Distributor.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))
@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@login_required
def delete_license(id): db.session.delete(License.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))
@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@login_required
def edit_license(id): lic = License.query.get_or_404(id); lic.is_used = (request.form.get("status") == "used"); db.session.commit(); return redirect(url_for("dashboard"))

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USERNAME and request.form.get("password") == ADMIN_PASSWORD: session["admin_logged_in"] = True; return redirect(url_for("dashboard"))
    return render_template("login.html")
@app.route("/admin/logout")
def logout(): session.pop("admin_logged_in", None); return redirect(FRONTEND_URL)
@app.route("/admin/export/<type>")
@login_required
def export_data(type):
    si = io.StringIO(); cw = csv.writer(si)
    if type == 'licenses':
        cw.writerow(['Date', 'Key', 'Plan', 'Amount', 'Distributor', 'Status', 'Version', 'Expiry'])
        for r in License.query.all(): cw.writerow([r.created_at, r.license_key, r.plan_type, r.amount_paid, r.distributor.name if r.distributor else 'Direct', r.is_used, r.software_version, r.expiry_date])
    elif type == 'distributors':
        cw.writerow(['Name', 'Code', 'Email', 'Earned', 'Paid', 'Balance'])
        for r in Distributor.query.all():
            earn = sum(safe_float(l.commission_earned) for l in r.licenses)
            cw.writerow([r.name, r.code, r.email, earn, r.commission_paid, earn - safe_float(r.commission_paid)])
    output = make_response(si.getvalue()); output.headers["Content-Disposition"] = f"attachment; filename={type}.csv"; output.headers["Content-type"] = "text/csv"; return output

# --- DISTRIBUTOR API ---
@app.route('/api/distributor/register', methods=['POST'])
def register_distributor():
    data = request.json; email = data.get('email').strip()
    if Distributor.query.count() > 450000: return jsonify({'success': False, 'message': 'Limit reached'})
    dist = Distributor.query.filter_by(email=email).first()
    if dist and dist.is_verified: return jsonify({'success': False, 'message': 'Email registered.'})
    otp = str(random.randint(100000, 999999))
    if not dist:
        while True:
            code = ''.join(random.choices(string.ascii_uppercase, k=4))
            if not Distributor.query.filter_by(code=code).first(): break
        dist = Distributor(code=code, name=data.get('name'), phone=data.get('phone'), email=email, is_verified=False, level=1)
        dist.set_password(data.get('password')); db.session.add(dist)
    else: dist.name=data.get('name'); dist.phone=data.get('phone'); dist.set_password(data.get('password'))
    dist.otp_code = otp; dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10); db.session.commit()
    send_brevo_email(email, "Verify Account", f"<h2>OTP: {otp}</h2>")
    return jsonify({'success': True, 'message': 'OTP Sent.'})

@app.route('/api/distributor/verify-registration', methods=['POST'])
def verify_registration():
    data = request.json; dist = Distributor.query.filter_by(email=data.get('email')).first()
    if not dist: return jsonify({'success': False, 'message': 'User not found'})
    if str(dist.otp_code) == str(data.get('otp')) and datetime.utcnow() <= dist.otp_expiry: dist.is_verified = True; dist.otp_code = None; db.session.commit(); return jsonify({'success': True, 'message': 'Verified!', 'code': dist.code})
    return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/api/distributor/login', methods=['POST'])
def api_distributor_login():
    data = request.json; dist = Distributor.query.filter_by(email=data.get('email')).first()
    if dist and dist.check_password(data.get('password')):
        if not dist.is_verified: return jsonify({'success': False, 'message': 'Not verified.'})
        check_level_update(dist) # Check if level changed
        dist.api_token = secrets.token_hex(16); db.session.commit(); return jsonify({'success': True, 'token': dist.api_token})
    return jsonify({'success': False, 'message': 'Invalid Login'})

@app.route('/api/distributor/data', methods=['GET'])
def api_get_distributor_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', ''); dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({'error': 'Invalid Token'}), 401
    page = request.args.get('page', 1, type=int)
    query = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc()); pagination = query.paginate(page=page, per_page=10, error_out=False)
    total_earned = sum(safe_float(l.commission_earned) for l in query.all())
    curr = dist.level; target = LEVELS[min(curr+1, 3)]['target']; month_sales = License.query.filter(License.distributor_id==dist.id, License.created_at >= datetime.utcnow().replace(day=1)).count()
    sales_data = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key, 'version': s.software_version, 'last_login': s.last_login_date.strftime('%Y-%m-%d') if s.last_login_date else '-', 'expiry': s.expiry_date.strftime('%Y-%m-%d') if s.expiry_date else '-'} for s in pagination.items]
    return jsonify({"name": dist.name, "code": dist.code, "discount": LEVELS[curr]['discount'], "commission_pct": LEVELS[curr]['commission'], "total_sales": query.count(), "commission_earned": total_earned, "commission_paid": safe_float(dist.commission_paid), "balance_due": total_earned - safe_float(dist.commission_paid), "sales_history": sales_data, "backend_url": request.host_url, "bank_info": {"bank_name": dist.bank_name, "account_holder": dist.account_holder, "account_number": dist.account_number, "ifsc": dist.ifsc_code, "upi": dist.upi_id}, "pagination": {"total_pages": pagination.pages, "has_next": pagination.has_next, "has_prev": pagination.has_prev}, "progress": {"current_level": LEVELS[curr]['name'], "month_sales": month_sales, "target": target, "next_level": LEVELS[min(curr+1, 3)]['name'], "is_max": curr==3}})

@app.route('/api/distributor/update-bank', methods=['POST'])
def update_bank():
    token = request.headers.get('Authorization', '').replace('Bearer ', ''); dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({'error': 'Invalid Token'}), 401
    data = request.json; dist.bank_name = data.get('bank_name'); dist.account_holder = data.get('account_holder'); dist.account_number = data.get('account_number'); dist.ifsc_code = data.get('ifsc_code'); dist.upi_id = data.get('upi_id'); db.session.commit(); return jsonify({'success': True})

@app.route('/api/send-otp', methods=['POST'])
def forgot_otp():
    email = request.json.get('email'); dist = Distributor.query.filter_by(email=email).first()
    if not dist: return jsonify({'success': False, 'message': 'Email not registered'})
    otp = str(random.randint(100000, 999999)); dist.otp_code = otp; dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10); db.session.commit()
    send_brevo_email(email, "Reset Password", f"<h2>OTP: {otp}</h2>"); return jsonify({'success': True, 'message': 'OTP sent'})

@app.route('/api/reset-with-otp', methods=['POST'])
def reset_with_otp():
    data = request.json; dist = Distributor.query.filter_by(email=data.get('email')).first()
    if not dist: return jsonify({'success': False})
    if str(dist.otp_code) == str(data.get('otp')) and datetime.utcnow() <= dist.otp_expiry:
        dist.set_password(data.get('new_password')); dist.otp_code = None; db.session.commit(); return jsonify({'success': True, 'message': 'Password changed'})
    return jsonify({'success': False, 'message': 'Invalid/Expired OTP'})

@app.route('/reset-db-now')
def reset_db():
    with app.app_context():
        try: db.drop_all(); db.create_all()
        except: pass
    return "DB Force Reset Complete"

if __name__ == '__main__': app.run(debug=True)
