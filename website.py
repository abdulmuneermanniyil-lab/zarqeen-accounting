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

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
FRONTEND_URL = "https://zarqeen.in"

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None 
)

CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)

raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300, "pool_size": 2, "max_overflow": 1}

db = SQLAlchemy(app)

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") 
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Login Rate Limiting
LOGIN_ATTEMPTS = {}
MAX_RETRIES = 5
LOCKOUT_TIME = timedelta(minutes=15)

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- LEVEL DEFINITIONS (3 LEVELS) ---
LEVELS = {
    1: {'name': 'Bronze', 'target': 0, 'commission': 15},
    2: {'name': 'Silver', 'target': 5, 'commission': 25},
    3: {'name': 'Gold',   'target': 20, 'commission': 35}
}

# --- MODELS ---
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

# --- HELPERS ---
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
    # Part 1: Prefix "AL" + Plan "BA"/"PR" (e.g., ALBA)
    p = "BA" if plan_type == 'basic' else "PR"
    part1 = f"AL{p}"

    # Part 2: Complete Distributor Code OR "ALIF"
    if dist_code:
        # Use the full code provided by the distributor
        part2 = dist_code.strip().upper()
    else:
        part2 = "ALIF"

    # Part 3 & 4: Random 4-char blocks to ensure uniqueness
    chars = string.ascii_uppercase + string.digits
    part3 = "".join(random.choices(chars, k=4))
    part4 = "".join(random.choices(chars, k=4))

    # Combine: ALBA-FULLCODE-X1Y2-Z3A4
    key = f"{part1}-{part2}-{part3}-{part4}"

    # Recursively ensure uniqueness
    if License.query.filter_by(license_key=key).first(): 
        return generate_unique_key(plan_type, dist_code)
    
    return key

def send_brevo_email(to_email, subject, html_content):
    if not BREVO_API_KEY: return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"api-key": BREVO_API_KEY, "content-type": "application/json"}
    payload = {"sender": {"name": "Zarqeen Support", "email": "zarqeensoftware@gmail.com"}, "to": [{"email": to_email}], "subject": subject, "htmlContent": html_content}
    try: requests.post(url, json=payload, headers=headers, timeout=5); return True
    except: return False

def check_level_update(dist):
    now = datetime.utcnow()
    if dist.last_level_check and dist.last_level_check.month == now.month and dist.last_level_check.year == now.year: return
    first = now.replace(day=1); last_month_end = first - timedelta(days=1); last_month_start = last_month_end.replace(day=1)
    count = License.query.filter(License.distributor_id==dist.id, License.created_at >= last_month_start, License.created_at <= last_month_end).count()
    current = dist.level; new_lvl = current
    
    if current < 3 and count >= LEVELS[current+1]['target']: new_lvl += 1
    elif current > 1 and count < LEVELS[current]['target']: new_lvl -= 1
    
    dist.level = new_lvl; dist.last_level_check = now; db.session.commit()

# --- ROUTES ---
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
            return jsonify({'valid': True, 'discount': dist.discount_percent, 'name': dist.name})
        return jsonify({'valid': False})
    except: return jsonify({'valid': False}), 500

@app.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.json
        
        # --- FIX STARTS HERE ---
        # We safely get the code. If it's None (from JS null), we use empty string ""
        raw_code = data.get('distributor_code')
        code = raw_code.strip().upper() if raw_code else ""
        # --- FIX ENDS HERE ---

        base_amount = 29900 if data.get('plan') == 'basic' else 59900
        final_amount = base_amount
        dist_id_str = "None"
        
        if code:
            dist = Distributor.query.filter_by(code=code).first()
            if dist and dist.is_verified:
                disc_pct = dist.discount_percent 
                final_amount = int(base_amount - ((base_amount * disc_pct) / 100))
                dist_id_str = str(dist.id)
        
        order = razorpay_client.order.create({
            'amount': final_amount, 
            'currency': 'INR', 
            'notes': {
                'plan': str(data.get('plan')), 
                'distributor_id': dist_id_str
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
            'razorpay_order_id': str(data['razorpay_order_id']),
            'razorpay_payment_id': str(data['razorpay_payment_id']),
            'razorpay_signature': str(data['razorpay_signature'])
        }
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        try:
            order = razorpay_client.order.fetch(data['razorpay_order_id'])
            notes = order.get('notes', {})
            dist_id = notes.get('distributor_id')
            amount_paid_paise = order.get('amount', 0)
        except Exception as e:
            print(f"Error fetching order: {e}")
            dist_id = "None"
            amount_paid_paise = 29900 if data.get('plan_type') == 'basic' else 59900

        dist_obj = None
        comm = 0.0
        
        if dist_id and str(dist_id) != "None":
            try:
                dist_obj = Distributor.query.get(int(dist_id))
                if dist_obj:
                    mrp = 299.0 if data.get('plan_type') == 'basic' else 599.0
                    st = Settings.query.first()
                    bonus = st.special_bonus_percent if st else 0
                    comm = (mrp * (LEVELS[dist_obj.level]['commission'] + bonus)) / 100
            except:
                pass

        new_key = generate_unique_key(data.get('plan_type'), dist_obj.code if dist_obj else None)
        
        new_lic = License(
            license_key=new_key, 
            plan_type=data.get('plan_type'), 
            payment_id=data['razorpay_payment_id'], 
            amount_paid=amount_paid_paise / 100.0, 
            commission_earned=comm, 
            distributor_id=dist_obj.id if dist_obj else None
        )
        
        db.session.add(new_lic)
        db.session.commit()
        
        return jsonify({'success': True, 'license_key': new_key})
        
    except Exception as e:
        print(f"VERIFY ERROR: {str(e)}") 
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download/license/<key>')
def download_license_file(key): return send_file(io.BytesIO(key.encode()), mimetype='text/plain', as_attachment=True, download_name='license.zarqeen')

from datetime import datetime
from flask import jsonify, request

@app.route('/api/validate_license', methods=['POST'])
def validate_license():
    data = request.json or {}
    license_key = data.get('license_key', '').strip()

    if not license_key:
        return jsonify({'valid': False, 'message': 'License key missing'}), 400

    lic = License.query.filter_by(license_key=license_key).first()

    if not lic:
        return jsonify({'valid': False, 'message': 'Invalid license'}), 404

    # Update audit info (safe to update every time)
    lic.software_version = data.get('version', 'Unknown')
    lic.last_login_date = datetime.utcnow()

    # 🚫 Already used
    if lic.is_used:
        db.session.commit()
        return jsonify({
            'valid': False,
            'message': 'License already used',
            'used_at': lic.used_at.isoformat() if lic.used_at else None
        })

    # ✅ ACTIVATE LICENSE
    lic.is_used = True
    lic.used_at = datetime.utcnow()

    # Plan duration
    duration_days = 365 if lic.plan_type == 'basic' else 1095

    db.session.commit()

    return jsonify({
        'valid': True,
        'plan': lic.plan_type,
        'duration_days': duration_days,
        'distributor_phone': lic.distributor.phone if lic.distributor else None,
        'distributor_name': lic.distributor.name if lic.distributor else "Zarqeen",
        'activated_at': lic.used_at.isoformat()
    })

LATEST_VERSION = "1.2.0" 

@app.route('/api/version_check', methods=['GET'])
def version_check():
    """
    This endpoint is called by the local desktop app.
    It returns the latest version details.
    """
    update_data = {
        "version": LATEST_VERSION,
        "download_url": "https://www.zarqeen.in/download", # Link to your installer
        "headline": "🚀 Supercharged Update Available!",
        "features": [
            "New Invoice Templates (A5 & Thermal)",
            "Faster Inventory Search",
            "Fixed 'None' display in GSTIN fields",
            "Split Address (City & Zip) support"
        ],
        "ad_image": "https://www.zarqeen.in/static/images/update_banner.png" 
    }
    return jsonify(update_data)





# --- ADMIN ---
@app.route("/admin/dashboard")
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    settings = Settings.query.first()
    if not settings: settings = Settings(); db.session.add(settings); db.session.commit()
    dist_data = []
    for d in distributors:
        earn = sum(safe_float(l.commission_earned) for l in d.licenses)
        dist_data.append({"obj": d, "earned": earn, "balance": earn - safe_float(d.commission_paid), "level_name": LEVELS.get(d.level, {'name':'Bronze'})['name']})
    return render_template("dashboard.html", licenses=licenses, distributors=dist_data, settings=settings)

@app.route("/admin/update_settings", methods=["POST"])
@login_required
def update_settings():
    s = Settings.query.first(); s.special_bonus_percent = int(request.form.get('bonus', 0)); s.special_message = request.form.get('message', ''); db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/admin/add_distributor", methods=["POST"])
@login_required
def add_distributor():
    try:
        code = request.form.get("code", "").strip().upper(); email = request.form.get("email", "").strip()
        if not code or not email: return redirect(url_for("dashboard"))
        if Distributor.query.filter((Distributor.code==code)|(Distributor.email==email)).first(): return redirect(url_for("dashboard"))
        
        disc_input = int(request.form.get("discount", 10))
        new_dist = Distributor(code=code, name=request.form.get("name"), phone=request.form.get("phone"), email=email, discount_percent=disc_input, is_verified=True, level=1)
        new_dist.set_password(request.form.get("password")); db.session.add(new_dist); db.session.commit()
    except: pass
    return redirect(url_for("dashboard"))

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@login_required
def edit_distributor(id):
    d = Distributor.query.get_or_404(id)
    
    if request.form.get("name"): d.name = request.form.get("name")
    if request.form.get("email"): d.email = request.form.get("email")
    if request.form.get("phone"): d.phone = request.form.get("phone")
    if request.form.get("discount"): 
        try: d.discount_percent = int(request.form.get("discount"))
        except: pass
    
    if "bank_name" in request.form: d.bank_name = request.form.get("bank_name")
    if "account_holder" in request.form: d.account_holder = request.form.get("account_holder")
    if "account_number" in request.form: d.account_number = request.form.get("account_number")
    if "ifsc_code" in request.form: d.ifsc_code = request.form.get("ifsc_code")
    if "upi_id" in request.form: d.upi_id = request.form.get("upi_id")
    
    add = request.form.get("add_payment")
    man = request.form.get("manual_paid_total")
    if add and safe_float(add) > 0: d.commission_paid += safe_float(add)
    elif man and man.strip(): d.commission_paid = safe_float(man)
    
    if request.form.get("password"): d.set_password(request.form.get("password"))
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@login_required
def delete_distributor(id): db.session.delete(Distributor.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))
@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@login_required
def delete_license(id): db.session.delete(License.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))
@app.route("/admin/edit_license/<int:id>", methods=["POST"])
@login_required
def edit_license(id): l = License.query.get_or_404(id); l.is_used = (request.form.get("status") == "used"); db.session.commit(); return redirect(url_for("dashboard"))

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.headers.get('X-Forwarded-For'): ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else: ip = request.remote_addr

    if ip in LOGIN_ATTEMPTS:
        attempt = LOGIN_ATTEMPTS[ip]
        if attempt['count'] >= MAX_RETRIES:
            if datetime.utcnow() - attempt['last_attempt'] < LOCKOUT_TIME:
                remaining = int((LOCKOUT_TIME - (datetime.utcnow() - attempt['last_attempt'])).total_seconds() / 60)
                msg = f"Too many failed attempts. Try again in {remaining} minutes."
                if request.is_json: return jsonify({'success': False, 'message': msg})
                return msg, 429
            else:
                LOGIN_ATTEMPTS[ip] = {'count': 0, 'last_attempt': datetime.utcnow()}

    username = ""
    password = ""
    if request.is_json:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
    else:
        username = request.form.get("username")
        password = request.form.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        if ip in LOGIN_ATTEMPTS: del LOGIN_ATTEMPTS[ip]
        session["admin_logged_in"] = True
        if request.is_json:
            return jsonify({'success': True, 'redirect': url_for('dashboard', _external=True)})
        return redirect(url_for("dashboard"))

    if ip not in LOGIN_ATTEMPTS: LOGIN_ATTEMPTS[ip] = {'count': 1, 'last_attempt': datetime.utcnow()}
    else:
        LOGIN_ATTEMPTS[ip]['count'] += 1
        LOGIN_ATTEMPTS[ip]['last_attempt'] = datetime.utcnow()

    msg = f"Invalid Credentials. Attempts remaining: {MAX_RETRIES - LOGIN_ATTEMPTS[ip]['count']}"
    if request.is_json: return jsonify({'success': False, 'message': msg})
    return msg, 401

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
    d = request.json; email = d.get('email', '').strip()
    if Distributor.query.count() > 450000: return jsonify({'success': False, 'message': 'Registration Limit Reached'})
    dist = Distributor.query.filter_by(email=email).first()
    if dist and dist.is_verified: return jsonify({'success': False, 'message': 'This Email is already registered. Please Login.'})
    otp = str(random.randint(100000, 999999))
    if not dist:
        while True:
            c = ''.join(random.choices(string.ascii_uppercase, k=4))
            if not Distributor.query.filter_by(code=c).first(): break
        dist = Distributor(code=c, name=d.get('name'), phone=d.get('phone'), email=email, is_verified=False, level=1, discount_percent=10)
        dist.set_password(d.get('password')); db.session.add(dist)
    else: dist.name=d.get('name'); dist.phone=d.get('phone'); dist.set_password(d.get('password'))
    dist.otp_code = otp; dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10); db.session.commit()
    sent = send_brevo_email(email, "Verification Code", f"Your OTP is: <b>{otp}</b>")
    if sent: return jsonify({'success': True, 'message': f'OTP sent to {email}. Check your Inbox/Spam.'})
    else: return jsonify({'success': True, 'message': f'OTP Generated (Email Failed): {otp}'})

@app.route('/api/distributor/verify-registration', methods=['POST'])
def verify_registration():
    d = request.json; dist = Distributor.query.filter_by(email=d.get('email')).first()
    if not dist: return jsonify({'success': False})
    if str(dist.otp_code) == str(d.get('otp')) and datetime.utcnow() <= dist.otp_expiry:
        dist.is_verified = True; db.session.commit()
        return jsonify({'success': True, 'code': dist.code})
    return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/api/distributor/login', methods=['POST'])
def api_distributor_login():
    d = request.json; dist = Distributor.query.filter_by(email=d.get('email')).first()
    if dist and dist.check_password(d.get('password')):
        if not dist.is_verified: return jsonify({'success': False, 'message': 'Unverified'})
        check_level_update(dist); dist.api_token = secrets.token_hex(16); db.session.commit()
        return jsonify({'success': True, 'token': dist.api_token})
    return jsonify({'success': False})

@app.route('/api/distributor/data', methods=['GET'])
def api_get_distributor_data():
    t = request.headers.get('Authorization', '').replace('Bearer ', ''); dist = Distributor.query.filter_by(api_token=t).first()
    if not dist: return jsonify({'error': 'Invalid'}), 401
    
    page = request.args.get('page', 1, type=int)
    q = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc())
    pg = q.paginate(page=page, per_page=10, error_out=False)
    
    earn = sum(safe_float(l.commission_earned) for l in q.all())
    cur = dist.level; tgt = LEVELS[min(cur+1, 3)]['target']
    msales = License.query.filter(License.distributor_id==dist.id, License.created_at>=datetime.utcnow().replace(day=1)).count()
    
    sd = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key, 'version': s.software_version, 'last_login': s.last_login_date.strftime('%Y-%m-%d') if s.last_login_date else '-', 'expiry': s.expiry_date.strftime('%Y-%m-%d') if s.expiry_date else '-'} for s in pg.items]

    return jsonify({
        "name": dist.name, "code": dist.code, "discount": dist.discount_percent, 
        "commission_pct": LEVELS[cur]['commission'],
        "total_sales": q.count(), "commission_earned": earn, "commission_paid": safe_float(dist.commission_paid), "balance_due": earn - safe_float(dist.commission_paid),
        "sales_history": sd, "backend_url": request.host_url,
        "bank_info": {"bank_name": dist.bank_name, "account_holder": dist.account_holder, "account_number": dist.account_number, "ifsc": dist.ifsc_code, "upi": dist.upi_id},
        "pagination": {"total_pages": pg.pages, "has_next": pg.has_next, "has_prev": pg.has_prev},
        "progress": {"current_level": LEVELS[cur]['name'], "month_sales": msales, "target": tgt, "next_level": LEVELS[min(cur+1, 3)]['name'], "is_max": cur==3}
    })

@app.route('/api/distributor/update-bank', methods=['POST'])
def update_bank():
    t = request.headers.get('Authorization', '').replace('Bearer ', ''); dist = Distributor.query.filter_by(api_token=t).first()
    if not dist: return jsonify({'error': 'Invalid'}), 401
    d = request.json; dist.bank_name=d.get('bank_name'); dist.account_holder=d.get('account_holder'); dist.account_number=d.get('account_number'); dist.ifsc_code=d.get('ifsc_code'); dist.upi_id=d.get('upi_id'); db.session.commit(); return jsonify({'success': True})

@app.route('/api/send-otp', methods=['POST'])
def forgot_otp():
    email = request.json.get('email'); dist = Distributor.query.filter_by(email=email).first()
    if not dist: return jsonify({'success': False, 'message': 'Email not registered.'})
    otp = str(random.randint(100000, 999999)); dist.otp_code = otp; dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10); db.session.commit()
    send_brevo_email(email, "Reset Password", f"OTP: {otp}")
    return jsonify({'success': True, 'message': f'OTP sent to {email}'})

@app.route('/api/reset-with-otp', methods=['POST'])
def reset_with_otp():
    d = request.json; dist = Distributor.query.filter_by(email=d.get('email')).first()
    if not dist: return jsonify({'success': False, 'message': 'User not found.'})
    if str(dist.otp_code) == str(d.get('otp')) and datetime.utcnow() <= dist.otp_expiry:
        dist.set_password(d.get('new_password')); dist.otp_code=None; db.session.commit()
        return jsonify({'success': True, 'message': 'Password updated successfully!'})
    return jsonify({'success': False, 'message': 'Invalid or Expired OTP'})

@app.route('/reset-db-now')
def reset_db():
    with app.app_context():
        try: db.drop_all(); db.create_all()
        except: pass
    return "DB Force Reset Complete"

if __name__ == '__main__': app.run(debug=True)
