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
from sqlalchemy import func

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
FRONTEND_URL = "https://zarqeen.in"

# --- CONFIG ---
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None 
)

# Database
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300, "pool_size": 2, "max_overflow": 1}

db = SQLAlchemy(app)

# Keys
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") 
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
CORS(app, resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}}, supports_credentials=True)

# --- CONSTANTS ---
MRP_BASIC = 299.0
MRP_PREMIUM = 599.0

# LEVEL DEFINITIONS
# Level 1 (Bronze): Start here. 
# Level 2 (Silver): > 5 Sales prev month. 
# Level 3 (Gold): > 20 Sales prev month.
LEVELS = {
    1: {'name': 'Bronze', 'discount': 10, 'commission': 15, 'target': 0},
    2: {'name': 'Silver', 'discount': 15, 'commission': 25, 'target': 5},
    3: {'name': 'Gold',   'discount': 20, 'commission': 40, 'target': 20}
}

# --- MODELS ---
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    special_bonus_percent = db.Column(db.Integer, default=0) # Christmas/Eid bonus
    special_message = db.Column(db.String(100), default="")  # e.g., "Christmas Offer Active!"

class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Auto-Generated Code
    code = db.Column(db.String(20), unique=True, nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Level System (1, 2, or 3)
    level = db.Column(db.Integer, default=1) 
    last_level_check = db.Column(db.DateTime, default=datetime.utcnow) # To track monthly updates
    
    # Banking
    bank_name = db.Column(db.String(100)); account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50)); ifsc_code = db.Column(db.String(20)); upi_id = db.Column(db.String(100))
    
    commission_paid = db.Column(db.Float, default=0.0)
    api_token = db.Column(db.String(100)); otp_code = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime); reset_token = db.Column(db.String(100))
    
    licenses = db.relationship("License", backref="distributor", lazy=True)

    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)
    
    # Get properties based on current level
    @property
    def current_discount(self): return LEVELS[self.level]['discount']
    @property
    def current_commission(self): return LEVELS[self.level]['commission']

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100))
    
    # Financials
    amount_paid = db.Column(db.Float, default=0.0) # Actual paid by customer
    mrp_at_purchase = db.Column(db.Float, default=0.0) # MRP at time of sale (for calc)
    commission_earned = db.Column(db.Float, default=0.0) # Calculated Commission
    
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    last_login_date = db.Column(db.DateTime)
    software_version = db.Column(db.String(20))
    distributor_id = db.Column(db.Integer, db.ForeignKey("distributor.id"))

# --- LOGIC ---
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("admin_logged_in"): return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

def safe_float(v):
    try: return float(v)
    except: return 0.0

def generate_distributor_code():
    # Generate random 4-letter code (e.g., ZXKY)
    while True:
        code = ''.join(random.choices(string.ascii_uppercase, k=4))
        if not Distributor.query.filter_by(code=code).first():
            return code

def generate_license_key(plan, dist_code=None):
    p = "BA" if plan == "basic" else "PR"
    d = dist_code[:4].upper() if dist_code else "ALIF"
    d = d.ljust(4, "X")
    r1 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    r2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    key = f"ZQ{p}-{d}-{r1}-{r2}"
    if License.query.filter_by(license_key=key).first(): return generate_license_key(plan, dist_code)
    return key

# --- LEVEL UP/DOWN LOGIC ---
def check_level_update(dist):
    now = datetime.utcnow()
    # Check if we already checked this month
    if dist.last_level_check and dist.last_level_check.month == now.month and dist.last_level_check.year == now.year:
        return # Already up to date for this month

    # Calculate Last Month Dates
    first = now.replace(day=1)
    last_month_end = first - timedelta(days=1)
    last_month_start = last_month_end.replace(day=1)

    # Count Sales in Prev Month
    sales_count = License.query.filter(
        License.distributor_id == dist.id,
        License.created_at >= last_month_start,
        License.created_at <= last_month_end
    ).count()

    old_level = dist.level
    new_level = old_level

    # Check for Promotion (Can go up 1 step)
    if old_level < 3:
        next_target = LEVELS[old_level + 1]['target']
        if sales_count >= next_target:
            new_level += 1
    
    # Check for Demotion (Can go down 1 step)
    # Only demote if they missed the target for their CURRENT level
    if old_level > 1:
        current_target = LEVELS[old_level]['target']
        if sales_count < current_target:
            new_level -= 1
            
    dist.level = new_level
    dist.last_level_check = now
    db.session.commit()

# --- ROUTES ---
@app.route("/")
def home(): return redirect(FRONTEND_URL)

@app.route("/api/get-config")
def get_config(): return jsonify({"key_id": RAZORPAY_KEY_ID})

# --- SELF REGISTRATION ---
@app.route("/api/distributor/register", methods=["POST"])
def register_distributor():
    data = request.json
    email = data.get('email').strip()
    
    if Distributor.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    # Auto-generate Code
    new_code = generate_distributor_code()
    
    new_dist = Distributor(
        code=new_code,
        name=data.get('name').strip(),
        phone=data.get('phone').strip(),
        email=email,
        level=1 # Start at Bronze
    )
    new_dist.set_password(data.get('password'))
    db.session.add(new_dist)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Account created! Please login.', 'code': new_code})

@app.route("/api/check_distributor", methods=["POST"])
def check_distributor():
    try:
        code = request.json.get("code", "").strip().upper()
        dist = Distributor.query.filter_by(code=code).first()
        if dist:
            return jsonify({"valid": True, "discount": dist.current_discount, "name": dist.name})
        return jsonify({"valid": False})
    except: return jsonify({"valid": False}), 500

@app.route("/create_order", methods=["POST"])
def create_order():
    try:
        plan = request.json.get("plan")
        code = request.json.get("distributor_code", "").strip().upper()
        
        mrp = MRP_BASIC if plan == "basic" else MRP_PREMIUM
        final_amount = mrp * 100 # Convert to Paise
        dist_id = "None"

        if code:
            dist = Distributor.query.filter_by(code=code).first()
            if dist:
                # Calculate Discount based on Distributor Level
                discount_amt = (mrp * dist.current_discount) / 100
                final_amount = int((mrp - discount_amt) * 100) # Paise
                dist_id = str(dist.id)

        order = razorpay_client.order.create({
            "amount": final_amount, "currency": "INR", "payment_capture": "1",
            "notes": {"plan": str(plan), "distributor_id": dist_id}
        })
        return jsonify(order)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    data = request.json
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        })
        order = razorpay_client.order.fetch(data['razorpay_order_id'])
        dist_id = order['notes'].get('distributor_id')
        
        dist_obj = None
        commission = 0.0
        mrp = MRP_BASIC if data.get('plan_type') == 'basic' else MRP_PREMIUM
        
        if dist_id and dist_id != "None":
            dist_obj = Distributor.query.get(int(dist_id))
            if dist_obj:
                # 1. Base Commission (based on Level)
                base_comm_percent = dist_obj.current_commission
                
                # 2. Special Bonus (Admin set)
                settings = Settings.query.first()
                bonus_percent = settings.special_bonus_percent if settings else 0
                
                # 3. Calculate on MRP
                total_percent = base_comm_percent + bonus_percent
                commission = (mrp * total_percent) / 100

        new_lic = License(
            license_key=generate_license_key(data.get('plan_type'), dist_obj.code if dist_obj else None),
            plan_type=data.get('plan_type'), payment_id=data['razorpay_payment_id'],
            amount_paid=order['amount'] / 100, 
            mrp_at_purchase=mrp,
            commission_earned=commission,
            distributor_id=dist_obj.id if dist_obj else None
        )
        db.session.add(new_lic)
        db.session.commit()
        return jsonify({"success": True, "license_key": new_lic.license_key})
    except Exception as e: return jsonify({"success": False, "message": str(e)})

# --- ADMIN PANEL ---
@app.route("/admin/dashboard")
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    settings = Settings.query.first() # Get Global Settings
    
    dist_data = []
    for d in distributors:
        # Calculate Total Earned from Commission Column
        earned = sum(safe_float(l.commission_earned) for l in d.licenses)
        dist_data.append({"obj": d, "earned": earned, "balance": earned - safe_float(d.commission_paid), "level_name": LEVELS[d.level]['name']})
        
    return render_template("dashboard.html", licenses=licenses, distributors=dist_data, settings=settings)

@app.route("/admin/update_settings", methods=["POST"])
@login_required
def update_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
    
    settings.special_bonus_percent = int(request.form.get('bonus', 0))
    settings.special_message = request.form.get('message', '')
    db.session.commit()
    flash('Settings Updated', 'success')
    return redirect(url_for('dashboard'))

@app.route("/admin/edit_distributor/<int:id>", methods=["POST"])
@login_required
def edit_distributor(id):
    dist = Distributor.query.get_or_404(id)
    # Manual Level Override (Optional)
    if request.form.get('level'): dist.level = int(request.form.get('level'))
    
    # ... (Rest of edit logic same as before, banking etc) ...
    dist.name = request.form.get('name')
    # ... mapping other fields ...
    add_pay = request.form.get('add_payment')
    if add_pay and float(add_pay) > 0: dist.commission_paid += float(add_pay)
    
    db.session.commit()
    return redirect(url_for('dashboard'))

# --- LOGIN & API ---
@app.route("/api/distributor/login", methods=["POST"])
def api_distributor_login():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get("email")).first()
    if dist and dist.check_password(data.get("password")):
        # Check Level Update on Login
        check_level_update(dist)
        
        dist.api_token = secrets.token_hex(16)
        db.session.commit()
        return jsonify({"success": True, "token": dist.api_token})
    return jsonify({"success": False})

@app.route("/api/distributor/data", methods=["GET"])
def api_get_distributor_data():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist: return jsonify({"error": "Invalid Token"}), 401

    query = License.query.filter_by(distributor_id=dist.id).order_by(License.created_at.desc())
    sales = query.all()
    
    # Calculate Total from Commission Column
    total_earned = sum(safe_float(l.commission_earned) for l in sales)
    
    # Get Next Level Info
    curr_lvl = dist.level
    next_lvl_target = LEVELS[min(curr_lvl+1, 3)]['target']
    
    # Current Month Sales for Progress
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0)
    month_sales = License.query.filter(License.distributor_id==dist.id, License.created_at>=month_start).count()

    return jsonify({
        "name": dist.name, "code": dist.code, 
        "level": LEVELS[curr_lvl]['name'], "discount": LEVELS[curr_lvl]['discount'],
        "commission_pct": LEVELS[curr_lvl]['commission'],
        "next_target": next_lvl_target, "current_month_sales": month_sales,
        "commission_earned": total_earned, "commission_paid": dist.commission_paid,
        "balance_due": total_earned - dist.commission_paid,
        "sales_history": [] # Pagination logic (keep same as previous)
    })

# --- RESET DB ---
@app.route("/reset-db-now")
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Create Default Settings
        if not Settings.query.first():
            db.session.add(Settings(special_bonus_percent=0))
            db.session.commit()
    return "DB Updated. New Level System Active."

if __name__ == "__main__":
    app.run(debug=True)
