import os, random, string, secrets, csv, io, requests, razorpay
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import text, inspect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "SECURE_ZARQEEN_ALIF_7788")

# RENDER ENVIRONMENT VARIABLES
BACKEND_URL = os.environ.get("BACKEND_URL", "").rstrip('/')
DOWNLOAD_LINK = os.environ.get("DOWNLOAD_LINK", "https://zarqeen.in")
VERSION = os.environ.get("VERSION", "1.2.0")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Session & CORS Security
app.config.update(SESSION_COOKIE_SAMESITE='None', SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True)
CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)

# Database Setup
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"): raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

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
    discount_percent = db.Column(db.Integer, default=10)
    commission_paid = db.Column(db.Float, default=0.0)
    api_token = db.Column(db.String(100))
    upi_id = db.Column(db.String(100))
    otp_code = db.Column(db.String(10)); otp_expiry = db.Column(db.DateTime)
    licenses = db.relationship('License', backref='distributor', lazy=True)
    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(60), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
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

# --- AUTO-MIGRATION ---
def migrate_database():
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('distributor')]
        migrations = [('is_active', 'BOOLEAN DEFAULT TRUE'),('upi_id', 'TEXT'),('discount_percent', 'INTEGER DEFAULT 10')]
        for col, dtype in migrations:
            if col not in cols:
                try: db.session.execute(text(f'ALTER TABLE distributor ADD COLUMN {col} {dtype}')); db.session.commit()
                except: db.session.rollback()
migrate_database()

# --- DECORATORS & HELPERS ---
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
    return f"{prefix}-{code}-{rand[:4]}-{rand[4:]}"

# --- ROUTES ---
@app.route('/')
def index(): return f"Zarqeen Security Server {VERSION} is Online.", 200

@app.route('/api/version_check')
def version_check():
    return jsonify({"version": VERSION, "download_url": DOWNLOAD_LINK, "message": f"🚀 Update v{VERSION} is live!"})

@app.route('/api/v1/config')
def get_public_config():
    return jsonify({"BACKEND_URL": BACKEND_URL or request.host_url.rstrip('/'), "DOWNLOAD_LINK": DOWNLOAD_LINK, "VERSION": VERSION, "RAZORPAY_KEY_ID": RAZORPAY_KEY_ID})

@app.route("/admin/login", methods=["POST"])
def admin_login_api():
    data = request.json or {}
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({'success': True, 'redirect': url_for('admin_dashboard', _external=True)})
    return jsonify({'success': False, 'message': 'Invalid Admin Credentials'}), 401

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

@app.route("/admin/update_settings", methods=["POST"])
@admin_login_required
def update_settings():
    s = db.session.get(Settings, 1)
    s.special_bonus_percent = int(request.form.get('bonus', 0)); db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/add_distributor", methods=["POST"])
@admin_login_required
def add_distributor():
    code = request.form.get("code", "").upper(); email = request.form.get("email")
    if Distributor.query.filter_by(code=code).first(): return "Code Exists", 400
    d = Distributor(code=code, name=request.form.get("name"), email=email, phone=request.form.get("phone"), discount_percent=int(request.form.get("discount", 10)))
    d.set_password(request.form.get("password")); db.session.add(d); db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@admin_login_required
def edit_distributor(id):
    d = db.session.get(Distributor, id)
    if request.form.get("name"): d.name = request.form.get("name")
    if "is_active" in request.form: d.is_active = (request.form.get("is_active") == "1")
    if request.form.get("manual_paid_total"): d.commission_paid = float(request.form.get("manual_paid_total"))
    db.session.commit(); return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@admin_login_required
def delete_distributor(id):
    db.session.delete(db.session.get(Distributor, id)); db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@admin_login_required
def edit_license(id):
    l = db.session.get(License, id); l.is_used = (request.form.get("status") == "used"); db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@admin_login_required
def delete_license(id):
    db.session.delete(db.session.get(License, id)); db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/api/distributor/login', methods=['POST'])
def dist_login():
    data = request.json or {}
    dist = Distributor.query.filter_by(email=data.get('email', '').strip()).first()
    if dist and dist.check_password(data.get('password')):
        if not dist.is_active: 
            return jsonify({'success': False, 'message': 'Account Disabled'}), 403
        dist.api_token = secrets.token_hex(16)
        db.session.commit()
        return jsonify({'success': True, 'token': dist.api_token})
    return jsonify({'success': False, 'message': 'Invalid Credentials'}), 401


@app.route('/api/distributor/data', methods=['GET'])
def get_dist_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist or not dist.is_active: return jsonify({'error': 'Unauthorized'}), 401
    
    page = request.args.get('page', 1, type=int)
    # Tier Logic (Example: 0-5 sales = Bronze, 5-20 = Silver, 20+ = Gold)
    total_sales = len(dist.licenses)
    if total_sales < 5: tier, comm_pct = "Bronze", 15
    elif total_sales < 20: tier, comm_pct = "Silver", 25
    else: tier, comm_pct = "Gold", 35

    earned = sum(l.commission_earned for l in dist.licenses)
    
    # Pagination (10 per page)
    pagination = License.query.filter_by(distributor_id=dist.id)\
        .order_by(License.created_at.desc())\
        .paginate(page=page, per_page=10, error_out=False)

    history = [{
        'date': l.created_at.strftime('%d-%b-%y'), 
        'plan': l.plan_type.upper(), 
        'commission': round(l.commission_earned, 2),
        'status': 'USED' if l.is_used else 'PENDING', 
        'key': l.license_key
    } for l in pagination.items]
    
    return jsonify({
        "name": dist.name, "code": dist.code, "tier": tier, "comm_pct": comm_pct,
        "bank": {"name": dist.bank_name or "", "holder": dist.account_holder or "", "acc": dist.account_number or "", "ifsc": dist.ifsc_code or "", "upi": dist.upi_id or ""},
        "financials": {"earned": round(earned, 2), "paid": round(dist.commission_paid, 2), "balance": round(earned - dist.commission_paid, 2)},
        "history": history,
        "pagination": {"total_pages": pagination.pages, "current_page": pagination.page}
    })

@app.route('/api/distributor/update-bank', methods=['POST'])
def update_bank():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({'success': False}), 401
    data = request.json
    dist.bank_name = data.get('bank_name')
    dist.account_holder = data.get('account_holder')
    dist.account_number = data.get('account_number')
    dist.ifsc_code = data.get('ifsc_code')
    dist.upi_id = data.get('upi_id')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/check_distributor', methods=['POST'])
def check_dist():
    # Looks for distributor by code and returns their discount percentage
    code = request.json.get('code','').strip().upper()
    d = Distributor.query.filter_by(code=code, is_active=True).first()
    if d:
        return jsonify({'valid': True, 'discount': d.discount_percent, 'name': d.name})
    return jsonify({'valid': False})


@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.json
    plan = data.get('plan')
    code = data.get('distributor_code', '').strip().upper()
    
    # Standard pricing in Paise
    amount = 29900 if plan == 'basic' else 59900
    dist_id = 'None'

    # Apply Discount if code is valid
    if code:
        dist = Distributor.query.filter_by(code=code, is_active=True).first()
        if dist:
            discount_val = int(amount * (dist.discount_percent / 100))
            amount -= discount_val
            dist_id = str(dist.id)

    try:
        order = razorpay_client.order.create({
            'amount': amount,
            'currency': 'INR',
            'notes': {'plan': plan, 'dist_id': dist_id}
        })
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/license/<key>')
def download_license(key):
    return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

@app.route('/admin/logout')
def admin_logout(): session.pop('admin_logged_in', None); return redirect("https://zarqeen.in")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
