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
    PERMANENT_SESSION_LIFETIME=604800,
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
    commission_earned = db.Column(db.Float, default=0.0)
    
    bank_name = db.Column(db.String(100)); account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50)); ifsc_code = db.Column(db.String(20)); upi_id = db.Column(db.String(100))
    
    commission_paid = db.Column(db.Float, default=0.0); api_token = db.Column(db.String(100))
    otp_code = db.Column(db.String(10)); otp_expiry = db.Column(db.DateTime); reset_token = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    is_enabled = db.Column(db.Boolean, default=True)
    level = db.Column(db.Integer, default=1); last_level_check = db.Column(db.DateTime, default=datetime.utcnow)
    licenses = db.relationship('License', backref='distributor', lazy=True)

    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)

class SystemMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(50), nullable=False) # Change this to force show again
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    link_text = db.Column(db.String(100))
    link_url = db.Column(db.String(255))
    style = db.Column(db.String(20), default="info") # info, success, warning

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(60), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100))
    user_email = db.Column(db.String(120))
    user_phone = db.Column(db.String(20)) 
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

def refresh_distributor_level(dist):
    """
    Checks if a new month has started since the last check.
    If yes, updates the distributor level based on previous month's sales.
    """
    now = datetime.utcnow()
    
    # If this is the first time or a new month has started
    if not dist.last_level_check or dist.last_level_check.month != now.month or dist.last_level_check.year != now.year:
        
        # Calculate start and end of the PREVIOUS month
        first_day_current_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day_prev_month = first_day_current_month - timedelta(days=1)
        first_day_prev_month = last_day_prev_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Count sales in the previous month
        prev_month_sales = License.query.filter(
            License.distributor_id == dist.id,
            License.created_at >= first_day_prev_month,
            License.created_at <= last_day_prev_month
        ).count()

        # Determine New Level for the Current Month
        new_level = 1 # Default Bronze
        if prev_month_sales >= LEVELS[3]['target']:
            new_level = 3 # Gold
        elif prev_month_sales >= LEVELS[2]['target']:
            new_level = 2 # Silver
        
        # Update distributor
        dist.level = new_level
        dist.last_level_check = now
        db.session.commit()

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
def index():
    return "Zarqeen Backend is Running", 200

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
        # 1. Signature Verification
        params_dict = {
            'razorpay_order_id': str(data['razorpay_order_id']),
            'razorpay_payment_id': str(data['razorpay_payment_id']),
            'razorpay_signature': str(data['razorpay_signature'])
        }
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # 2. Fetch Order and Plan Info
        plan_type = data.get('plan_type')
        dist_id = None
        amount_collected = 0.0

        try:
            order_data = razorpay_client.order.fetch(data['razorpay_order_id'])
            notes = order_data.get('notes', {})
            dist_id = notes.get('distributor_id')
            amount_collected = float(order_data.get('amount', 0)) / 100.0
        except Exception as e:
            # Fallback if Razorpay fetch fails
            amount_collected = 299.0 if plan_type == 'basic' else 599.0

        # 3. Distributor & Commission Logic
        dist_obj = None
        comm_earned = 0.0
        
        if dist_id and str(dist_id) != "None":
            dist_obj = Distributor.query.get(int(dist_id))
            if dist_obj:
                # Always calculate based on MRP
                mrp = 299.0 if plan_type == 'basic' else 599.0
                
                # Ensure level is current
                refresh_distributor_level(dist_obj)
                
                # Get Global Bonus from Settings
                st = Settings.query.first()
                bonus_pct = st.special_bonus_percent if st else 0
                
                # Get Base Level Rate (15, 25, or 35)
                base_rate = LEVELS.get(dist_obj.level, LEVELS[1])['commission']
                
                # Total Rate = Base + Bonus
                total_rate = base_rate + bonus_pct
                
                # Final Commission Calculation
                comm_earned = (mrp * total_rate) / 100

        # 4. Generate Key
        new_key = generate_unique_key(plan_type, dist_obj.code if dist_obj else None)
        
        # 5. Save Single License Instance
        new_lic = License(
            license_key=new_key, 
            plan_type=plan_type, 
            payment_id=data['razorpay_payment_id'], 
            amount_paid=amount_collected, 
            commission_earned=round(comm_earned, 2), 
            distributor_id=dist_obj.id if dist_obj else None,
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_lic)
        db.session.commit()
        
        return jsonify({'success': True, 'license_key': new_key})
        
    except Exception as e:
        db.session.rollback()
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
    
    # Capture user info and software info from the request
    u_email = data.get('user_email', '').strip()
    u_phone = data.get('user_phone', '').strip()
    version = data.get('version', 'Unknown')

    if not license_key:
        return jsonify({'valid': False, 'message': 'License key missing'}), 400

    # 1. Look up the license in the database
    lic = License.query.filter_by(license_key=license_key).first()

    if not lic:
        return jsonify({'valid': False, 'message': 'License key not found in our records.'}), 404

    # 2. Prevent re-activation of used keys
    if lic.is_used:
        used_date = lic.used_at.strftime("%d-%b-%Y") if lic.used_at else "an unknown date"
        return jsonify({
            'valid': False,
            'message': f'This license was already activated on {used_date}.'
        }), 400

    # 3. ACTIVATE THE LICENSE & SAVE USER DETAILS
    # This links the license to the specific customer in your Render database
    lic.is_used = True
    lic.used_at = datetime.utcnow()
    lic.software_version = version
    lic.last_login_date = datetime.utcnow()
    lic.user_email = u_email  # Saved to License table
    lic.user_phone = u_phone  # Saved to License table

    # 4. HANDLE DISTRIBUTOR COMMISSION & INFO
    # Set default info for Direct sales
    dist_info = {
        'code': 'DIRECT',
        'name': 'Zarqeen Support',
        'phone': 'zarqeensoftware@gmail.com' 
    }

    if lic.distributor:
        dist = lic.distributor
        
        # Calculate commission based on distributor's discount level
        # (e.g., 10% of 999 = 99.9 commission)
        commission = lic.amount_paid * (dist.discount_percent / 100.0)
        
        # Update the License record
        lic.commission_earned = commission
        
        # Update the Distributor's total earnings balance
        dist.commission_earned += commission 
        
        # Update info for the API response
        dist_info = {
            'code': dist.code,
            'name': dist.name,
            'phone': dist.phone
        }

    # 5. Save everything to the Web Database
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # Log the error for your internal debugging
        print(f"DATABASE COMMIT ERROR: {e}") 
        return jsonify({'valid': False, 'message': 'Internal Server Error: Failed to save activation.'}), 500

    # 6. RETURN COMPLETE DATA TO THE DESKTOP APP
    # These fields are used by the software to update the local 'History' table and support number
    return jsonify({
        'valid': True,
        'plan': lic.plan_type,             # 'basic' or 'premium'
        'amount': lic.amount_paid,         # Actual price paid (useful for history)
        'distributor_code': dist_info['code'],
        'distributor_name': dist_info['name'],
        'distributor_phone': dist_info['phone'],
        'activated_at': lic.used_at.isoformat(),
        'expiry_date': lic.expiry_date.isoformat() # From your model property
    })

# --- site_backend.py (On Render) ---
LATEST_VERSION = "1.1.0" 

@app.route('/api/version_check', methods=['GET'])
def version_check():
    update_data = {
        "version": LATEST_VERSION,
        "download_url": "https://www.zarqeen.in",
        # NEW: Add the exact message you want displayed locally
        "message": "🚀 New Update v1.2.0: Now with split address support, auto-comma removal, and faster search!",
        "headline": "Supercharged Update Available!", # Fallback
        "features": [
            "New Invoice Templates (A5 & Thermal)",
            "Faster Inventory Search",
            "Fixed 'None' display in GSTIN fields",
            "Split Address (City & Zip) support"
        ],
        "ad_image": "https://www.zarqeen.in/static/images/update_banner.png" 
    }
    return jsonify(update_data)


@app.route('/api/download-link')
def get_download_link():
    url = os.environ.get('DOWNLOAD_LINK', 'fallback.exe')
    return jsonify({"download_url": url})



# --- ADMIN ---
@app.route("/admin/dashboard")
def dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for('login'))

    licenses = License.query.order_by(License.created_at.desc()).all()
    # Query all distributors from DB
    all_distributors = Distributor.query.all()
    
    settings = Settings.query.first()
    if not settings:
        settings = Settings(special_bonus_percent=0, special_message="Welcome")
        db.session.add(settings)
        db.session.commit()

    # Prepare the list for the template
    dist_data = []
    for d in all_distributors:
        # Sum commission earned from all licenses of THIS distributor
        total_earned = sum(safe_float(l.commission_earned) for l in d.licenses)
        balance = total_earned - safe_float(d.commission_paid)
        
        dist_data.append({
            "obj": d, 
            "earned": total_earned, 
            "balance": balance, 
            "level_name": LEVELS.get(d.level, LEVELS[1])['name']
        })

    # CRITICAL: Ensure you are passing 'distributors=dist_data'
    return render_template("dashboard.html", 
                           licenses=licenses, 
                           distributors=dist_data, 
                           settings=settings)

@app.route('/admin/update_settings', methods=['POST'])
def update_settings():
    # Manual check for logged in admin
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')

    s = Settings.query.first()
    if not s:
        s = Settings()
        db.session.add(s)

    # SAFE CONVERSION: Check if the value is empty before calling int()
    bonus_val = request.form.get('bonus', '0').strip()
    s.special_bonus_percent = int(bonus_val) if bonus_val and bonus_val.isdigit() else 0
    
    # Matches your DB column 'special_message'
    s.special_message = request.form.get('bonus_name', '').strip()
    
    db.session.commit()
    return redirect('/admin/dashboard')

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
def edit_distributor(id):
    # Security: Manual session check for better cross-domain/mobile compatibility
    if not session.get("admin_logged_in"):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    d = Distributor.query.get_or_404(id)
    
    # Basic Information
    if request.form.get("name"): d.name = request.form.get("name").strip()
    if request.form.get("email"): d.email = request.form.get("email").strip()
    if request.form.get("phone"): d.phone = request.form.get("phone").strip()
    
    # Discount Percentage
    discount = request.form.get("discount")
    if discount:
        try:
            d.discount_percent = int(discount)
        except ValueError:
            pass
    
    # Banking Details
    if "upi_id" in request.form: d.upi_id = request.form.get("upi_id").strip()
    # Adding these in case you decide to add inputs for them later
    if request.form.get("bank_name"): d.bank_name = request.form.get("bank_name").strip()
    if request.form.get("account_holder"): d.account_holder = request.form.get("account_holder").strip()
    if request.form.get("account_number"): d.account_number = request.form.get("account_number").strip()
    if request.form.get("ifsc_code"): d.ifsc_code = request.form.get("ifsc_code").strip()
    
    # --- PAYMENT LOGIC ---
    add_payment = request.form.get("add_payment", "").strip()
    manual_paid = request.form.get("manual_paid_total", "").strip()

    # Priority 1: If Admin typed an amount to "Add", increment the existing total
    if add_payment:
        try:
            val = float(add_payment)
            if val > 0:
                # Increment the existing value
                d.commission_paid = float(d.commission_paid or 0) + val
        except ValueError:
            pass
    # Priority 2: If no "Add" value, check if the "Total Paid" was manually edited
    elif manual_paid:
        try:
            d.commission_paid = float(manual_paid)
        except ValueError:
            pass
    # ----------------------

    # Password Update (Only if provided)
    new_password = request.form.get("password")
    if new_password and len(new_password.strip()) > 0:
        d.set_password(new_password.strip())
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Update Error: {e}")

    return redirect(url_for("dashboard"))

@app.route("/admin/delete_distributor/<int:id>", methods=["POST"])
@login_required
def delete_distributor(id): db.session.delete(Distributor.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))
    
@app.route("/admin/delete_license/<int:id>", methods=["POST"])
@login_required
def delete_license(id): db.session.delete(License.query.get_or_404(id)); db.session.commit(); return redirect(url_for("dashboard"))

@app.route('/admin/edit_license/<int:license_id>', methods=['POST'])
@login_required
def edit_license(license_id):
    # This matches the 'status' name in the dashboard.html dropdown
    new_status = request.form.get('status') 
    license_obj = License.query.get(license_id)
    
    if license_obj:
        # If dropdown is 'used', set is_used to True, else False
        license_obj.is_used = (new_status == 'used')
        db.session.commit()
        
    return redirect('/admin/dashboard')


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    # 1. Identify User IP
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr

    # 2. Check Rate Limiting Lockout
    if ip in LOGIN_ATTEMPTS:
        attempt = LOGIN_ATTEMPTS[ip]
        if attempt['count'] >= MAX_RETRIES:
            if datetime.utcnow() - attempt['last_attempt'] < LOCKOUT_TIME:
                remaining = int((LOCKOUT_TIME - (datetime.utcnow() - attempt['last_attempt'])).total_seconds() / 60)
                msg = f"Too many failed attempts. Try again in {remaining} minutes."
                if request.is_json: 
                    return jsonify({'success': False, 'message': msg})
                return msg, 429
            else:
                # Lockout expired, reset counter
                LOGIN_ATTEMPTS[ip] = {'count': 0, 'last_attempt': datetime.utcnow()}

    # 3. Handle GET request (Show message or handle as needed)
    if request.method == "GET":
        return jsonify({'message': 'Admin login endpoint active.'})

    # 4. Handle POST request (JSON Login)
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Missing login data'}), 400

    username = data.get("username")
    password = data.get("password")

    # 5. Check Credentials
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        # Success: Clear attempts and set session
        if ip in LOGIN_ATTEMPTS: 
            del LOGIN_ATTEMPTS[ip]
            
        session["admin_logged_in"] = True
        session.permanent = True # Important for mobile cookie persistence
        
        return jsonify({
            'success': True, 
            'redirect': url_for('dashboard', _external=True)
        })
    
    # 6. Failure: Track attempt and return error
    attempts_data = LOGIN_ATTEMPTS.get(ip, {'count': 0})
    attempts_data['count'] += 1
    attempts_data['last_attempt'] = datetime.utcnow()
    LOGIN_ATTEMPTS[ip] = attempts_data
    
    return jsonify({
        'success': False, 
        'message': f"Invalid Credentials. Attempt {attempts_data['count']}/{MAX_RETRIES}"
    }), 401

@app.route("/admin/logout")
def logout(): session.pop("admin_logged_in", None); return redirect(FRONTEND_URL)

@app.route("/admin/export/<type>")
def export_data(type):
    # Security: Ensure only logged-in admin can export
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    si = io.StringIO()
    cw = csv.writer(si)
    
    if type == 'licenses':
        # Expanded headers to include User Contact and Activation details
        cw.writerow([
            'Date Created', 'License Key', 'Plan Type', 'Amount Paid', 
            'Commission Earned (₹)', 'Distributor Name', 'Distributor Code', 
            'User Email', 'User Phone', 'Status', 'Activation Date', 
            'Software Version', 'Expiry Date', 'Razorpay Payment ID'
        ])
        
        licenses = License.query.order_by(License.created_at.desc()).all()
        for r in licenses:
            cw.writerow([
                r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                r.license_key,
                r.plan_type.upper(),
                r.amount_paid,
                r.commission_earned,
                r.distributor.name if r.distributor else 'Direct',
                r.distributor.code if r.distributor else 'DIRECT',
                r.user_email or 'N/A',  # NEW
                r.user_phone or 'N/A',  # NEW
                'Installed' if r.is_used else 'Pending',
                r.used_at.strftime('%Y-%m-%d %H:%M:%S') if r.used_at else 'Not Activated', # NEW
                r.software_version or 'N/A',
                r.expiry_date.strftime('%Y-%m-%d') if r.expiry_date else 'N/A',
                r.payment_id or '-'
            ])

    elif type == 'distributors':
        # Headers for Distributors including Banking & Level info (Kept as per your code)
        cw.writerow([
            'Name', 'Distributor Code', 'Email', 'Phone', 'Current Level', 
            'Discount %', 'Total Earned (₹)', 'Total Paid (₹)', 'Balance Due (₹)', 
            'Bank Name', 'Account Holder', 'Account Number', 'IFSC Code', 'UPI ID', 'Verified'
        ])
        
        distributors = Distributor.query.all()
        for r in distributors:
            # Calculate financials
            total_earn = sum(safe_float(l.commission_earned) for l in r.licenses)
            total_paid = safe_float(r.commission_paid)
            balance = total_earn - total_paid
            # Handle levels (assuming LEVELS constant exists in your website.py)
            level_name = LEVELS.get(r.level, LEVELS[1])['name'] if 'LEVELS' in globals() else f"Level {r.level}"
            
            cw.writerow([
                r.name,
                r.code,
                r.email,
                r.phone,
                level_name,
                r.discount_percent,
                round(total_earn, 2),
                round(total_paid, 2),
                round(balance, 2),
                r.bank_name or '-',
                r.account_holder or '-',
                f"'{r.account_number}" if r.account_number else '-', 
                r.ifsc_code or '-',
                r.upi_id or '-',
                'Yes' if r.is_verified else 'No'
            ])

    output = make_response(si.getvalue())
    # Generate filename with current date
    file_tag = datetime.utcnow().strftime('%Y%m%d_%H%M')
    output.headers["Content-Disposition"] = f"attachment; filename=zarqeen_{type}_{file_tag}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

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
    
    # 1. Refresh Level & Get Settings
    refresh_distributor_level(dist)
    settings = Settings.query.first()
    bonus_pct = settings.special_bonus_percent if settings else 0
    
    page = request.args.get('page', 1, type=int)
    q = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc())
    pg = q.paginate(page=page, per_page=10, error_out=False)
    
    # Financials
    earn = sum(safe_float(l.commission_earned) for l in q.all())
    cur = dist.level
    base_rate = LEVELS[cur]['commission']
    tgt = LEVELS[min(cur+1, 3)]['target']
    msales = License.query.filter(License.distributor_id==dist.id, License.created_at>=datetime.utcnow().replace(day=1)).count()
    
    # Reduced Sales History (Matching your dashboard requirement)
    sd = [{'date': s.created_at.strftime('%Y-%m-%d'), 'plan': s.plan_type, 'amount': s.amount_paid, 'status': 'INSTALLED' if s.is_used else 'PENDING', 'key': s.license_key} for s in pg.items]

    return jsonify({
        "name": dist.name, 
        "code": dist.code, 
        "discount": dist.discount_percent, 
        "base_comm": base_rate,
        "bonus_percent": bonus_pct,
        "bonus_name": settings.special_message if settings else "",
        "commission_pct": base_rate + bonus_pct, # Combined Rate
        "total_sales": q.count(), 
        "commission_earned": earn, 
        "commission_paid": safe_float(dist.commission_paid), 
        "balance_due": earn - safe_float(dist.commission_paid),
        "sales_history": sd, 
        "backend_url": request.host_url,
        "bank_info": {"bank_name": dist.bank_name, "account_holder": dist.account_holder, "account_number": dist.account_number, "ifsc": dist.ifsc_code, "upi": dist.upi_id},
        "pagination": {"total_pages": pg.pages, "has_next": pg.has_next, "has_prev": pg.has_prev},
        "progress": {"current_level": LEVELS[cur]['name'], "month_sales": msales, "target": tgt, "next_level": LEVELS[min(cur+1, 3)]['name'], "is_max": cur==3}
    })


@app.route("/admin/view_distributor/<int:id>")
def view_distributor(id):
    if not session.get("admin_logged_in"): return redirect('/admin/login')
    d = Distributor.query.get_or_404(id)
    # Calculate financials for the detail view
    total_earned = sum(safe_float(l.commission_earned) for l in d.licenses)
    balance = total_earned - safe_float(d.commission_paid)
    return render_template("view_distributor.html", d=d, earned=total_earned, balance=balance, levels=LEVELS)

@app.route("/admin/toggle_distributor/<int:id>", methods=["POST"])
def toggle_distributor(id):
    if not session.get("admin_logged_in"): 
        return redirect('/admin/login')
        
    d = Distributor.query.get_or_404(id)
    # Check if column exists, then toggle
    if hasattr(d, 'is_enabled'):
        d.is_enabled = not d.is_enabled
    else:
        # Fallback if you haven't run the migration yet
        return "Database migration needed. Please add is_enabled column.", 500
        
    db.session.commit()
    return redirect('/admin/dashboard')


    
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

@app.route('/api/system_message', methods=['GET'])
def get_system_message():
    # Fetch the most recent active message
    msg = SystemMessage.query.filter_by(is_active=True).order_by(SystemMessage.id.desc()).first()
    if msg:
        return jsonify({
            "message_id": msg.message_id,
            "content": msg.content,
            "style": msg.style,
            "show_link": True if msg.link_url else False,
            "link_text": msg.link_text,
            "link_url": msg.link_url
        })
    return jsonify({"content": ""}) # Return empty if no message

@app.route('/admin/update_broadcast', methods=['POST'])
def update_broadcast():
    content = request.form.get('content')
    m_id = request.form.get('message_id')
    
    # Deactivate all old messages
    SystemMessage.query.update({SystemMessage.is_active: False})
    
    # Create new broadcast
    new_msg = SystemMessage(
        message_id=m_id,
        content=content,
        link_text=request.form.get('link_text'),
        link_url=request.form.get('link_url'),
        style=request.form.get('style', 'info'),
        is_active=True
    )
    db.session.add(new_msg)
    db.session.commit()
    flash("Broadcast message updated!")
    return redirect('/admin/dashboard')


@app.route('/reset-db-now')
def reset_db():
    with app.app_context():
        try: db.drop_all(); db.create_all()
        except: pass
    return "DB Force Reset Complete"

@app.route('/sys/fix-db')
def fix_db():
    # This command adds the missing column directly to your Postgres DB
    db.session.execute(db.text('ALTER TABLE distributor ADD COLUMN IF NOT EXISTS commission_earned FLOAT DEFAULT 0.0'))
    db.session.commit()
    return "Database updated successfully!"

if __name__ == '__main__': app.run(debug=True)

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True, # Required for 'None'
    PERMANENT_SESSION_LIFETIME=604800 # 7 Days
)
