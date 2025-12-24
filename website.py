import os
import random
import string
import secrets
import csv
import io
import requests # Required for Brevo API
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
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
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
# 2. KEYS & CREDENTIALS
# -------------------------------------------------
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") 

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# -------------------------------------------------
# 3. DATABASE MODELS
# -------------------------------------------------
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    discount_percent = db.Column(db.Integer, default=10)

    # Banking
    bank_name = db.Column(db.String(100))
    account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    upi_id = db.Column(db.String(100))

    commission_paid = db.Column(db.Float, default=0.0)
    api_token = db.Column(db.String(100))

    # OTP
    otp_code = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime)
    reset_token = db.Column(db.String(100))

    licenses = db.relationship("License", backref="distributor", lazy=True)

    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(60), unique=True, nullable=False) # Increased length
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100))
    amount_paid = db.Column(db.Float, default=0.0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Tracking
    used_at = db.Column(db.DateTime)
    last_login_date = db.Column(db.DateTime)
    software_version = db.Column(db.String(20))
    
    distributor_id = db.Column(db.Integer, db.ForeignKey("distributor.id"))

    @property
    def expiry_date(self):
        if not self.used_at: return None
        days = 365 if self.plan_type == 'basic' else 1095
        return self.used_at + timedelta(days=days)

# -------------------------------------------------
# 4. HELPER FUNCTIONS
# -------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("admin_logged_in"): return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

def safe_float(v):
    try: return float(v)
    except: return 0.0

def generate_unique_key(plan_type, dist_code=None):
    # Format: ZQBA-ALIF-XXXXXX-XXXXXX (Longer Key: 6 chars per block)
    p = "BA" if plan_type == "basic" else "PR"
    d = dist_code[:4].upper() if dist_code else "ALIF"
    d = d.ljust(4, "X")
    r1 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    r2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    key = f"ZQ{p}-{d}-{r1}-{r2}"
    if License.query.filter_by(license_key=key).first():
        return generate_unique_key(plan_type, dist_code)
    return key

# --- BREVO EMAIL SENDER ---
def send_otp_email(email, otp):
    if not BREVO_API_KEY:
        print(">>> ERROR: BREVO_API_KEY missing. OTP logged only.")
        return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"api-key": BREVO_API_KEY, "content-type": "application/json"}
    payload = {
        "sender": {"name": "Zarqeen Support", "email": "zarqeensoftware@gmail.com"},
        "to": [{"email": email}],
        "subject": "Your Zarqeen Verification Code",
        "htmlContent": f"<h2>Code: {otp}</h2><p>Expires in 10 minutes.</p>"
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=5)
        return True
    except: return False

# -------------------------------------------------
# 5. ROUTES
# -------------------------------------------------
@app.route("/")
def home():
    return redirect(FRONTEND_URL)

@app.route("/api/get-config")
def get_config():
    return jsonify({"key_id": RAZORPAY_KEY_ID})

@app.route("/api/check_distributor", methods=["POST"])
def check_distributor():
    try:
        code = request.json.get("code", "").strip().upper()
        dist = Distributor.query.filter_by(code=code).first()
        if dist: return jsonify({"valid": True, "discount": dist.discount_percent, "name": dist.name})
        return jsonify({"valid": False})
    except Exception as e: return jsonify({"valid": False, "error": str(e)}), 500

@app.route("/create_order", methods=["POST"])
def create_order():
    try:
        data = request.json
        plan = data.get("plan")
        code = data.get("distributor_code", "").strip().upper() if data.get("distributor_code") else ""
        base_amount = 29900 if plan == "basic" else 59900
        final_amount = base_amount
        dist_id_str = "None"
        if code:
            dist = Distributor.query.filter_by(code=code).first()
            if dist:
                final_amount = int(base_amount - ((base_amount * dist.discount_percent) / 100))
                dist_id_str = str(dist.id)
        order = razorpay_client.order.create({
            "amount": final_amount, "currency": "INR", "payment_capture": "1",
            "notes": {"plan": str(plan), "distributor_id": dist_id_str}
        })
        return jsonify(order)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    data = request.json
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'], 'razorpay_payment_id': data['razorpay_payment_id'], 'razorpay_signature': data['razorpay_signature']
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
        return jsonify({"success": True, "license_key": new_key})
    except Exception as e: return jsonify({"success": False, "message": str(e)})

@app.route("/download/license/<key>")
def download_license_file(key):
    return send_file(io.BytesIO(key.encode()), mimetype="text/plain", as_attachment=True, download_name="license.zarqeen")

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json
    key_input = data.get('license_key', '').strip()
    lic = License.query.filter_by(license_key=key_input).first()
    if lic:
        # Update Version & Login Time regardless of status
        lic.software_version = data.get('version', 'Unknown')
        lic.last_login_date = datetime.utcnow()
        
        if lic.is_used:
            db.session.commit()
            return jsonify({'valid': False, 'message': 'License already used.'})
        
        lic.is_used = True
        lic.used_at = datetime.utcnow()
        db.session.commit()
        
        dur = 365 if lic.plan_type == 'basic' else 1095
        s_name = lic.distributor.name if lic.distributor else "Zarqeen Official"
        s_con = lic.distributor.phone if lic.distributor else "zarqeensoftware@gmail.com"
        return jsonify({'valid': True, 'plan': lic.plan_type, 'duration_days': dur, 'support_info': {'name': s_name, 'contact': s_con}})
    return jsonify({'valid': False, 'message': 'Invalid License Key'})

# -------------------------------------------------
# 6. ADMIN PANEL
# -------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USERNAME and request.form.get("password") == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/admin/dashboard")
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    dist_data = []
    for d in distributors:
        earned = sum(safe_float(l.amount_paid) for l in d.licenses) * 0.20
        dist_data.append({"obj": d, "earned": earned, "balance": earned - safe_float(d.commission_paid)})
    return render_template("dashboard.html", licenses=licenses, distributors=dist_data)

@app.route("/admin/add_distributor", methods=["POST"])
@login_required
def add_distributor():
    try:
        code = request.form.get("code", "").strip().upper()
        email = request.form.get("email", "").strip()
        if not code or not email: return redirect(url_for("dashboard"))
        if Distributor.query.filter((Distributor.code==code)|(Distributor.email==email)).first(): return redirect(url_for("dashboard"))
        new_dist = Distributor(
            code=code, name=request.form.get("name"), phone=request.form.get("phone"), email=email,
            discount_percent=int(request.form.get("discount", 10)), bank_name=request.form.get("bank_name"),
            account_holder=request.form.get("account_holder"), account_number=request.form.get("account_number"),
            ifsc_code=request.form.get("ifsc_code"), upi_id=request.form.get("upi_id")
        )
        new_dist.set_password(request.form.get("password"))
        db.session.add(new_dist); db.session.commit()
    except: pass
    return redirect(url_for("dashboard"))

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@login_required
def edit_distributor(id):
    dist = Distributor.query.get_or_404(id)
    dist.name = request.form.get("name"); dist.email = request.form.get("email"); dist.phone = request.form.get("phone")
    if request.form.get("discount"): dist.discount_percent = int(request.form.get("discount"))
    dist.bank_name = request.form.get("bank_name"); dist.account_holder = request.form.get("account_holder")
    dist.account_number = request.form.get("account_number"); dist.ifsc_code = request.form.get("ifsc_code"); dist.upi_id = request.form.get("upi_id")
    add_pay = request.form.get("add_payment"); man_pay = request.form.get("manual_paid_total")
    if add_pay and safe_float(add_pay) > 0: dist.commission_paid = safe_float(dist.commission_paid) + safe_float(add_pay)
    elif man_pay and man_pay.strip(): dist.commission_paid = safe_float(man_pay)
    if request.form.get("password"): dist.set_password(request.form.get("password"))
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@login_required
def delete_distributor(id):
    dist = Distributor.query.get_or_404(id)
    for l in License.query.filter_by(distributor_id=id).all(): l.distributor_id = None
    db.session.delete(dist); db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@login_required
def delete_license(id):
    db.session.delete(License.query.get_or_404(id)); db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@login_required
def edit_license(id):
    lic = License.query.get_or_404(id)
    status = request.form.get("status")
    if status == "used": lic.is_used = True
    elif status == "active": lic.is_used = False
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/logout")
def logout(): session.pop("admin_logged_in", None); return redirect(FRONTEND_URL)

@app.route("/admin/export/<type>")
@login_required
def export_data(type):
    si = io.StringIO(); cw = csv.writer(si)
    if type == 'licenses':
        cw.writerow(['Date', 'Key', 'Plan', 'Amount', 'Distributor', 'Status', 'Version', 'Last Login', 'Expiry'])
        for r in License.query.all():
            d = r.distributor.name if r.distributor else 'Direct'
            exp = r.expiry_date.strftime('%Y-%m-%d') if r.expiry_date else '-'
            cw.writerow([r.created_at, r.license_key, r.plan_type, r.amount_paid, d, r.is_used, r.software_version, r.last_login_date, exp])
    elif type == 'distributors':
        cw.writerow(['Name', 'Code', 'Email', 'Total Earned', 'Paid', 'Balance'])
        for r in Distributor.query.all():
            earn = sum(safe_float(l.amount_paid) for l in r.licenses) * 0.20
            cw.writerow([r.name, r.code, r.email, earn, r.commission_paid, earn - safe_float(r.commission_paid)])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={type}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# -------------------------------------------------
# 7. DISTRIBUTOR API
# -------------------------------------------------
@app.route("/api/distributor/login", methods=["POST"])
def api_distributor_login():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get("email")).first()
    if dist and dist.check_password(data.get("password")):
        dist.api_token = secrets.token_hex(16); db.session.commit()
        return jsonify({"success": True, "token": dist.api_token})
    return jsonify({"success": False, "message": "Invalid Login"})

@app.route("/api/distributor/register", methods=["POST"])
def register_distributor():
    data = request.json
    if Distributor.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'message': 'Email exists'})
    
    # Auto-generate code
    while True:
        code = ''.join(random.choices(string.ascii_uppercase, k=4))
        if not Distributor.query.filter_by(code=code).first(): break
    
    new_dist = Distributor(
        code=code, name=data.get('name'), phone=data.get('phone'), email=data.get('email'),
        discount_percent=10 # Bronze default
    )
    new_dist.set_password(data.get('password'))
    db.session.add(new_dist); db.session.commit()
    return jsonify({'success': True, 'code': code})

@app.route("/api/distributor/data", methods=["GET"])
def api_get_distributor_data():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({"error": "Invalid Token"}), 401
    
    page = request.args.get("page", 1, type=int)
    query = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc())
    pagination = query.paginate(page=page, per_page=10, error_out=False)
    
    total_earned = sum(safe_float(l.amount_paid) for l in query.all()) * 0.20
    sales_data = []
    for s in pagination.items:
        exp = s.expiry_date.strftime('%Y-%m-%d') if s.expiry_date else '-'
        sales_data.append({'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key, 'version': s.software_version, 'last_login': s.last_login_date.strftime('%Y-%m-%d %H:%M') if s.last_login_date else '-', 'expiry': exp})

    return jsonify({
        "name": dist.name, "code": dist.code, "discount": dist.discount_percent,
        "total_sales": query.count(), "commission_earned": total_earned, "commission_paid": safe_float(dist.commission_paid),
        "balance_due": total_earned - safe_float(dist.commission_paid), "sales_history": sales_data, "backend_url": request.host_url,
        "bank_info": {"bank_name": dist.bank_name, "account_holder": dist.account_holder, "account_number": dist.account_number, "ifsc": dist.ifsc_code, "upi": dist.upi_id},
        "pagination": {"total_pages": pagination.pages, "has_next": pagination.has_next, "has_prev": pagination.has_prev}
    })

@app.route("/api/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email")
    dist = Distributor.query.filter_by(email=email).first()
    if not dist: return jsonify({"success": False, "message": "Email not registered"})
    otp = str(random.randint(100000, 999999))
    dist.otp_code = otp; dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    print(f">>> DEBUG OTP for {email}: {otp}")
    if send_otp_email(email, otp): return jsonify({"success": True, "message": "OTP sent"})
    return jsonify({"success": True, "message": "OTP generated (Check Logs)"})

@app.route("/api/reset-with-otp", methods=["POST"])
def reset_with_otp():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get("email")).first()
    if not dist: return jsonify({"success": False})
    if str(dist.otp_code) == str(data.get("otp")) and datetime.utcnow() <= dist.otp_expiry:
        dist.set_password(data.get("new_password")); dist.otp_code = None; db.session.commit()
        return jsonify({"success": True, "message": "Password Changed"})
    return jsonify({"success": False, "message": "Invalid/Expired OTP"})

@app.route("/reset-db-now")
def reset_db():
    with app.app_context():
        try: 
            db.drop_all()
            db.create_all()
        except: pass
    return "DB Updated with long keys and version fields"

if __name__ == "__main__":
    app.run(debug=True)
