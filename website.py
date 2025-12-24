import os, random, string, secrets, csv, io, requests, razorpay
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- CONFIG ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

FRONTEND_URL = "https://zarqeen.in"

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # IMPORTANT: works locally + Render
)

CORS(app)

raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# ---------------- LEVELS ----------------
LEVELS = {
    1: {"name": "Bronze", "discount": 10, "commission": 15, "target": 0},
    2: {"name": "Silver", "discount": 15, "commission": 25, "target": 5},
    3: {"name": "Gold", "discount": 20, "commission": 40, "target": 20}
}

# ---------------- MODELS ----------------
class Distributor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256))
    is_verified = db.Column(db.Boolean, default=False)
    level = db.Column(db.Integer, default=1)
    api_token = db.Column(db.String(64))
    commission_paid = db.Column(db.Float, default=0.0)
    otp_code = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime)

    bank_name = db.Column(db.String(100))
    account_holder = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    upi_id = db.Column(db.String(100))

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(60), unique=True)
    plan_type = db.Column(db.String(20))
    amount_paid = db.Column(db.Float)
    distributor_id = db.Column(db.Integer, db.ForeignKey("distributor.id"))
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)

# ---------------- INIT DB ----------------
with app.app_context():
    db.create_all()

# ---------------- HELPERS ----------------
def generate_key(plan, code="ALIF"):
    p = "BA" if plan == "basic" else "PR"
    r = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    return f"ZQ{p}-{code[:4]}-{r}"

def send_email(email, subject, text):
    if not BREVO_API_KEY:
        print("OTP:", text)
        return
    try:
        requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "content-type": "application/json"},
            json={
                "sender": {"name": "Zarqeen", "email": "zarqeensoftware@gmail.com"},
                "to": [{"email": email}],
                "subject": subject,
                "htmlContent": text
            }
        )
    except:
        pass

# ---------------- ROUTES ----------------
@app.route("/api/get-config")
def get_config():
    return jsonify({"key_id": RAZORPAY_KEY_ID})

@app.route("/create_order", methods=["POST"])
def create_order():
    data = request.json
    plan = data.get("plan")
    amount = 29900 if plan == "basic" else 59900

    order = razorpay_client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": 1
    })

    return jsonify({
        "id": order["id"],
        "amount": order["amount"],
        "currency": "INR"
    })

@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    data = request.json
    key = generate_key(data["plan_type"])
    lic = License(
        license_key=key,
        plan_type=data["plan_type"],
        amount_paid=(299 if data["plan_type"] == "basic" else 599)
    )
    db.session.add(lic)
    db.session.commit()
    return jsonify({"success": True, "license_key": key})

@app.route("/download/license/<key>")
def download_license(key):
    return send_file(
        io.BytesIO(key.encode()),
        as_attachment=True,
        download_name="license.zarqeen",
        mimetype="text/plain"
    )

@app.route("/api/distributor/register", methods=["POST"])
def register():
    d = request.json
    if Distributor.query.filter_by(email=d["email"]).first():
        return jsonify({"success": False, "message": "Email exists"})
    code = "".join(random.choices(string.ascii_uppercase, k=4))
    dist = Distributor(
        code=code,
        name=d["name"],
        phone=d["phone"],
        email=d["email"]
    )
    dist.set_password(d["password"])
    dist.otp_code = str(random.randint(100000, 999999))
    dist.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.add(dist)
    db.session.commit()
    send_email(dist.email, "OTP", f"Your OTP: {dist.otp_code}")
    return jsonify({"success": True})

@app.route("/api/distributor/verify-registration", methods=["POST"])
def verify():
    d = request.json
    dist = Distributor.query.filter_by(email=d["email"]).first()
    if not dist:
        return jsonify({"success": False})
    if dist.otp_code == d["otp"]:
        dist.is_verified = True
        db.session.commit()
        return jsonify({"success": True, "code": dist.code})
    return jsonify({"success": False})

@app.route("/api/distributor/login", methods=["POST"])
def dist_login():
    d = request.json
    dist = Distributor.query.filter_by(email=d["email"]).first()
    if dist and dist.check_password(d["password"]) and dist.is_verified:
        dist.api_token = secrets.token_hex(16)
        db.session.commit()
        return jsonify({"success": True, "token": dist.api_token})
    return jsonify({"success": False})

@app.route("/api/distributor/data")
def dist_data():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    dist = Distributor.query.filter_by(api_token=token).first()
    if not dist:
        return jsonify({"error": "unauthorized"}), 401
    sales = License.query.filter_by(distributor_id=dist.id).all()
    return jsonify({
        "name": dist.name,
        "code": dist.code,
        "discount": LEVELS[dist.level]["discount"],
        "total_sales": len(sales),
        "commission_earned": 0,
        "commission_paid": dist.commission_paid,
        "balance_due": 0,
        "sales_history": [],
        "pagination": {"total_pages": 1, "has_next": False, "has_prev": False},
        "progress": {"current_level": LEVELS[dist.level]["name"], "month_sales": 0, "target": 0, "next_level": "Silver", "is_max": False}
    })

if __name__ == "__main__":
    app.run(debug=True)
