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
# APP SETUP
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_ME")

FRONTEND_URL = "https://zarqeen.in"

CORS(
    app,
    resources={r"/*": {"origins": ["https://zarqeen.in", "https://www.zarqeen.in"]}},
    supports_credentials=True
)

# -------------------------------------------------
# DATABASE
# -------------------------------------------------
raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# KEYS
# -------------------------------------------------
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    discount_percent = db.Column(db.Integer, default=10)

    bank_name = db.Column(db.String(100))
    account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    upi_id = db.Column(db.String(100))

    commission_paid = db.Column(db.Float, default=0.0)
    api_token = db.Column(db.String(100))

    otp_code = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime)

    licenses = db.relationship("License", backref="distributor", lazy=True)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(50), unique=True, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100))
    amount_paid = db.Column(db.Float, default=0.0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    distributor_id = db.Column(db.Integer, db.ForeignKey("distributor.id"))

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap


def safe_float(v):
    try:
        return float(v)
    except:
        return 0.0


def generate_license(plan, dist_code=None):
    p = "BA" if plan == "basic" else "PR"
    d = dist_code[:4].upper() if dist_code else "ALIF"
    d = d.ljust(4, "X")
    r1 = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    r2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    key = f"ZQ{p}-{d}-{r1}-{r2}"
    if License.query.filter_by(license_key=key).first():
        return generate_license(plan, dist_code)
    return key


# -------------------------------------------------
# BREVO EMAIL (SAFE)
# -------------------------------------------------
def send_otp_email(email, otp):
    if not BREVO_API_KEY:
        print("BREVO_API_KEY missing")
        return

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": "Zarqeen Support", "email": "zarqeensoftware@gmail.com"},
        "to": [{"email": email}],
        "subject": "Your Zarqeen OTP",
        "htmlContent": f"""
        <p>Your OTP code is:</p>
        <h2>{otp}</h2>
        <p>This OTP is valid for 10 minutes.</p>
        """
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=5)
    except Exception as e:
        print("BREVO ERROR:", e)

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/")
def home():
    return redirect(FRONTEND_URL)


@app.route("/api/get-config")
def get_config():
    return jsonify({"key_id": RAZORPAY_KEY_ID})


@app.route("/api/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email")
    dist = Distributor.query.filter_by(email=email).first()
    if not dist:
        return jsonify({"success": False, "message": "Email not registered"})

    otp = str(random.randint(100000, 999999))
    dist.otp_code = otp
    dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    print(f">>> DEBUG OTP for {email}: {otp}")
    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "OTP sent to email"})


@app.route("/api/reset-with-otp", methods=["POST"])
def reset_with_otp():
    data = request.json
    dist = Distributor.query.filter_by(email=data.get("email")).first()
    if not dist:
        return jsonify({"success": False, "message": "User not found"})

    if datetime.utcnow() > dist.otp_expiry:
        return jsonify({"success": False, "message": "OTP expired"})

    if dist.otp_code != data.get("otp"):
        return jsonify({"success": False, "message": "Invalid OTP"})

    dist.set_password(data.get("new_password"))
    dist.otp_code = None
    dist.otp_expiry = None
    db.session.commit()

    return jsonify({"success": True, "message": "Password reset successful"})


# -------------------------------------------------
# ADMIN LOGIN
# -------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME
            and request.form.get("password") == ADMIN_PASSWORD
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/admin/dashboard")
@login_required
def dashboard():
    licenses = License.query.order_by(License.created_at.desc()).all()
    distributors = Distributor.query.all()
    data = []
    for d in distributors:
        earned = sum(l.amount_paid for l in d.licenses) * 0.20
        data.append({
            "obj": d,
            "earned": earned,
            "balance": earned - safe_float(d.commission_paid)
        })
    return render_template("dashboard.html", licenses=licenses, distributors=data)


# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
