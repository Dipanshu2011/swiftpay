import os, re, json, hmac, hashlib, secrets, time, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="SwiftPays API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://swiftpays.pages.dev", "http://localhost", "http://127.0.0.1:3000"],
    allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"],
)

def get_firebase():
    if not firebase_admin._apps:
        path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not path or not os.path.isfile(path):
            raise RuntimeError("Firebase credentials not found")
        firebase_admin.initialize_app(credentials.Certificate(path))
    return firestore.client()

def now_utc():
    return datetime.now(timezone.utc)

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310000)
        return hmac.compare_digest(test.hex(), digest_hex)
    except Exception:
        return False

def make_session(user_id):
    secret = os.getenv("SESSION_SECRET")
    if not secret:
        raise HTTPException(503, "Backend SESSION_SECRET is not configured")
    payload = json.dumps({"sub": user_id, "exp": int(time.time()) + 86400}, separators=(",", ":")).encode()
    body = secrets.token_urlsafe(8) + "." + payload.hex()
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig

def normalize_mobile(mobile):
    value = re.sub(r"\D", "", mobile or "")
    if len(value) == 12 and value.startswith("91"):
        value = value[2:]
    if not re.fullmatch(r"[6-9][0-9]{9}", value):
        raise HTTPException(400, "Please enter a valid 10-digit Indian mobile number.")
    return value

def send_telegram(chat_id, text):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise HTTPException(503, "Telegram OTP service is not configured on the backend.")
    data = urllib.parse.urlencode({"chat_id": str(chat_id), "text": text}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode())
        if not result.get("ok"):
            raise RuntimeError("Telegram delivery failed")
    except Exception:
        raise HTTPException(502, "Telegram message could not be delivered.")

class TurnstileRequest(BaseModel):
    token: str

class LinkStart(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    mobile: str
    password: str = Field(min_length=8, max_length=128)

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    mobile: str
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    mobile: str
    password: str

class ForgotRequest(BaseModel):
    mobile: str

class ResetRequest(BaseModel):
    mobile: str
    otp: str = Field(pattern=r"^[0-9]{6}$")
    password: str = Field(min_length=8, max_length=128)

class TelegramComplete(BaseModel):
    link_token: str
    telegram_user_id: str
    telegram_username: str | None = None

@app.get("/")
def home():
    return {"status": "success", "message": "Welcome to SwiftPays API"}

@app.get("/health")
def health():
    return {"status": "healthy", "service": "SwiftPays Backend"}

@app.get("/firebase-status")
def firebase_status():
    try:
        get_firebase().collection("_health").document("check").get(timeout=10)
        return {"status": "connected", "service": "Firebase Firestore"}
    except Exception:
        raise HTTPException(503, "Firebase connection failed")

@app.post("/verify-turnstile")
def verify_turnstile(data: TurnstileRequest):
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret:
        raise HTTPException(503, "Turnstile is not configured")
    if not data.token.strip():
        raise HTTPException(400, "Please complete Cloudflare security verification.")
    payload = urllib.parse.urlencode({"secret": secret, "response": data.token}).encode()
    req = urllib.request.Request("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode())
        if not result.get("success"):
            raise HTTPException(400, "Cloudflare verification failed. Please try again.")
        if result.get("hostname") not in ("swiftpays.pages.dev", "localhost"):
            raise HTTPException(400, "Invalid verification hostname.")
        return {"success": True, "message": "Verification successful"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Verification service unavailable")

@app.post("/telegram/link/start")
def telegram_link_start(data: LinkStart):
    db = get_firebase()
    mobile = normalize_mobile(data.mobile)
    if not os.getenv("TELEGRAM_BOT_USERNAME"):
        raise HTTPException(503, "Telegram bot username is not configured on the backend.")
    if db.collection("users").document("m_" + mobile).get().exists:
        raise HTTPException(409, "This number is already registered.")
    token = secrets.token_urlsafe(32)
    db.collection("telegram_link_tokens").document(hashlib.sha256(token.encode()).hexdigest()).set({
        "name": data.name.strip(), "mobile": mobile, "password_hash": hash_password(data.password),
        "created_at": firestore.SERVER_TIMESTAMP, "expires_at": now_utc() + timedelta(minutes=10),
        "used": False
    })
    username = os.getenv("TELEGRAM_BOT_USERNAME").lstrip("@")
    return {"url": f"https://t.me/{username}?start=link_{token}", "expires_in_seconds": 600}

@app.post("/telegram/link/complete")
def telegram_link_complete(data: TelegramComplete, x_telegram_link_secret: str = Header(default="")):
    # Call this from your Telegram bot after /start link_<token>.
    supplied = os.getenv("TELEGRAM_LINK_SECRET", "")
    header_secret = x_telegram_link_secret
    if not supplied or not hmac.compare_digest(supplied, header_secret):
        raise HTTPException(401, "Unauthorized Telegram bot callback.")
    db = get_firebase()
    token_hash = hashlib.sha256(data.link_token.encode()).hexdigest()
    ref = db.collection("telegram_link_tokens").document(token_hash)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(400, "Invalid or expired Telegram linking token.")
    info = snap.to_dict()
    if info.get("used") or info.get("expires_at") < now_utc():
        raise HTTPException(400, "Telegram linking token has expired.")
    uid = str(data.telegram_user_id).strip()
    if not uid.isdigit():
        raise HTTPException(400, "Invalid Telegram user ID.")
    if db.collection("telegram_users").document(uid).get().exists:
        raise HTTPException(409, "This Telegram account is already linked to another SwiftPays account.")
    mobile_ref = db.collection("users").document("m_" + info["mobile"])
    counter_ref = db.collection("_counters").document("users")
    @firestore.transactional
    def create_user(transaction):
        if mobile_ref.get(transaction=transaction).exists:
            raise HTTPException(409, "This number is already registered.")
        counter = counter_ref.get(transaction=transaction)
        number = int((counter.to_dict() or {}).get("last", 100000)) + 1
        user_id = f"SWP{number}"
        user_ref = db.collection("users").document("m_" + info["mobile"])
        transaction.set(user_ref, {
            "user_id": user_id, "name": info["name"], "mobile": info["mobile"],
            "password_hash": info["password_hash"], "telegram_user_id": uid,
            "telegram_username": data.telegram_username, "created_at": firestore.SERVER_TIMESTAMP,
            "status": "active", "balance_paise": 0
        })
        transaction.set(counter_ref, {"last": number})
        transaction.set(db.collection("telegram_users").document(uid), {"user_id": user_id, "mobile": info["mobile"]})
        transaction.update(ref, {"used": True, "completed_at": firestore.SERVER_TIMESTAMP})
        return user_id
    try:
        user_id = create_user(db.transaction())
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "Account creation failed. Please try again.")
    return {"success": True, "user_id": user_id}

@app.post("/auth/register")
def register(data: RegisterRequest):
    # Registration must follow Telegram linking; this endpoint intentionally does not accept a Telegram ID from the browser.
    raise HTTPException(400, "Please connect your Telegram account first, then complete linking from the Telegram bot.")

@app.post("/auth/login")
def login(data: LoginRequest):
    db = get_firebase()
    mobile = normalize_mobile(data.mobile)
    snap = db.collection("users").document("m_" + mobile).get()
    if not snap.exists:
        raise HTTPException(404, "This number is not registered. Please create an account first.")
    user = snap.to_dict()
    if user.get("status") != "active":
        raise HTTPException(403, "This account is currently unavailable. Please contact support.")
    if not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(401, "Incorrect password. Please try again.")
    return {"success": True, "message": "Login successful.", "token": make_session(user["user_id"]),
            "user": {"user_id": user["user_id"], "name": user["name"], "mobile": user["mobile"]}}

@app.post("/auth/forgot-password")
def forgot_password(data: ForgotRequest):
    db = get_firebase()
    mobile = normalize_mobile(data.mobile)
    snap = db.collection("users").document("m_" + mobile).get()
    # Same generic response prevents account enumeration.
    generic = "If this number is registered and linked to Telegram, an OTP will be sent."
    if not snap.exists:
        return {"success": True, "message": generic}
    user = snap.to_dict()
    if not user.get("telegram_user_id"):
        return {"success": True, "message": generic}
    otp = f"{secrets.randbelow(1000000):06d}"
    salt = secrets.token_bytes(16)
    otp_hash = hashlib.pbkdf2_hmac("sha256", otp.encode(), salt, 150000).hex()
    db.collection("password_resets").document("m_" + mobile).set({
        "otp_hash": salt.hex() + "$" + otp_hash, "expires_at": now_utc() + timedelta(minutes=5),
        "attempts": 0, "created_at": firestore.SERVER_TIMESTAMP
    })
    send_telegram(user["telegram_user_id"], f"SwiftPays password reset OTP: {otp}\nValid for 5 minutes. Do not share it.")
    return {"success": True, "message": generic}

@app.post("/auth/reset-password")
def reset_password(data: ResetRequest):
    db = get_firebase()
    mobile = normalize_mobile(data.mobile)
    ref = db.collection("password_resets").document("m_" + mobile)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(400, "Invalid or expired OTP.")
    record = snap.to_dict()
    if record.get("expires_at") < now_utc() or record.get("attempts", 0) >= 5:
        ref.delete()
        raise HTTPException(400, "Invalid or expired OTP.")
    if not verify_password(data.otp, record.get("otp_hash", "")):
        ref.update({"attempts": firestore.Increment(1)})
        raise HTTPException(400, "Incorrect OTP.")
    user_ref = db.collection("users").document("m_" + mobile)
    if not user_ref.get().exists:
        ref.delete()
        raise HTTPException(400, "Invalid or expired OTP.")
    user_ref.update({"password_hash": hash_password(data.password), "password_changed_at": firestore.SERVER_TIMESTAMP})
    ref.delete()
    return {"success": True, "message": "Password reset successful. Please log in."}
