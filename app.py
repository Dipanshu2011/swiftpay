import os, re, json, hmac, hashlib, secrets, time, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
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

class AdminLoginRequest(BaseModel):
    firebase_id_token: str = Field(min_length=20, max_length=10000)

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

@app.post("/admin/login")
def admin_login(data: AdminLoginRequest):
    """
    Verify a Firebase Authentication ID token and authorize exactly one owner.
    OWNER_UID must be configured in the Render environment.
    """
    owner_uid = os.getenv("OWNER_UID", "").strip()
    if not owner_uid:
        raise HTTPException(503, "Backend OWNER_UID is not configured.")

    token = data.firebase_id_token.strip()
    if not token:
        raise HTTPException(401, "Firebase login token is missing.")

    try:
        # Initialize Firebase Admin credentials before verifying the token.
        get_firebase()
        decoded = firebase_auth.verify_id_token(token, check_revoked=True)
    except firebase_admin.exceptions.FirebaseError:
        raise HTTPException(401, "Firebase session is invalid or expired. Please sign in again.")
    except RuntimeError:
        raise HTTPException(503, "Firebase Admin credentials are not configured on the backend.")
    except Exception:
        raise HTTPException(401, "Firebase session could not be verified. Please sign in again.")

    verified_uid = str(decoded.get("uid", "")).strip()
    if not verified_uid or not hmac.compare_digest(verified_uid, owner_uid):
        raise HTTPException(403, "This account is not authorized as the SwiftPays owner.")

    return {
        "authorized": True,
        "role": "owner",
        "message": "Owner authentication successful."
    }


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




# ==========================================
# SWIFTPAYS CONFIGURATION SAVE SYSTEM
# Firebase Firestore + Owner Authentication
# ==========================================

from typing import Optional
from fastapi import Depends

CONFIG_COLLECTION = "siteSettings"
CONFIG_DOCUMENT = "platform"

class PlatformConfig(BaseModel):
    # Website
    website_name: str = Field(default="SwiftPays", min_length=1, max_length=80)
    support_email: str = Field(default="", max_length=150)
    support_link: str = Field(default="", max_length=500)
    currency: str = Field(default="INR", pattern="^INR$")
    timezone: str = Field(default="Asia/Kolkata", max_length=80)

    # Telegram (public username only)
    support_bot_username: str = Field(default="", max_length=80)

    # Turnstile (public key only)
    turnstile_site_key: str = Field(default="", max_length=300)
    turnstile_enabled: bool = True

    # UPI Manual Payment
    upi_id: str = Field(default="", max_length=150)
    upi_payee_name: str = Field(default="", max_length=150)
    upi_qr_url: str = Field(default="", max_length=1000)

    # Deposit
    deposit_enabled: bool = True
    min_deposit: float = Field(default=10, ge=1, le=10000000)
    max_deposit: float = Field(default=10000, ge=1, le=10000000)

    # Withdrawal
    withdrawal_enabled: bool = True
    min_withdrawal: float = Field(default=100, ge=1, le=10000000)
    max_withdrawal: float = Field(default=10000, ge=1, le=10000000)
    withdrawal_tax_percent: float = Field(default=0, ge=0, le=100)
    withdrawal_fixed_tax: float = Field(default=0, ge=0, le=10000000)
    daily_withdrawal_limit: float = Field(default=20000, ge=1, le=10000000)
    withdrawal_upi_enabled: bool = True
    withdrawal_mobile_enabled: bool = False
    withdrawal_verification_required: bool = True

    # Security
    registration_enabled: bool = True
    maintenance_mode: bool = False

    # Manual review only
    deposit_approval: str = Field(default="manual", pattern="^manual$")
    withdrawal_approval: str = Field(default="manual", pattern="^manual$")


def require_platform_owner(
    authorization: Optional[str] = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Owner authentication required."
        )

    token = authorization[7:].strip()
    owner_uid = os.getenv("OWNER_UID", "").strip()

    if not owner_uid:
        raise HTTPException(
            status_code=503,
            detail="Owner is not configured."
        )

    try:
        get_firebase()
        decoded = firebase_auth.verify_id_token(
            token,
            check_revoked=True
        )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired Firebase session."
        )

    uid = str(decoded.get("uid", ""))

    if not hmac.compare_digest(uid, owner_uid):
        raise HTTPException(
            status_code=403,
            detail="Owner access denied."
        )

    return uid


def validate_platform_config(config):
    if config.min_deposit > config.max_deposit:
        raise HTTPException(
            422,
            "Minimum deposit cannot exceed maximum deposit."
        )

    if config.min_withdrawal > config.max_withdrawal:
        raise HTTPException(
            422,
            "Minimum withdrawal cannot exceed maximum withdrawal."
        )

    if config.daily_withdrawal_limit < config.min_withdrawal:
        raise HTTPException(
            422,
            "Daily withdrawal limit cannot be below minimum withdrawal."
        )

    if config.withdrawal_fixed_tax >= config.min_withdrawal:
        raise HTTPException(
            422,
            "Fixed withdrawal tax must be below minimum withdrawal."
        )

    if config.upi_id and not re.fullmatch(
        r"[A-Za-z0-9._-]{2,256}@[A-Za-z0-9.-]{2,100}",
        config.upi_id
    ):
        raise HTTPException(422, "Invalid UPI ID.")

    for url in [config.upi_qr_url, config.support_link]:
        if url and not url.startswith("https://"):
            raise HTTPException(422, "Links must use HTTPS.")


def platform_config_ref():
    return get_firebase().collection(
        CONFIG_COLLECTION
    ).document(CONFIG_DOCUMENT)


def load_platform_config():
    snapshot = platform_config_ref().get()
    saved = snapshot.to_dict() if snapshot.exists else {}

    defaults = PlatformConfig().model_dump()
    allowed = {
        key: value
        for key, value in (saved or {}).items()
        if key in defaults
    }

    defaults.update(allowed)
    return defaults


@app.get("/admin/config")
def admin_get_config(
    owner_uid: str = Depends(require_platform_owner)
):
    try:
        settings = load_platform_config()
    except Exception:
        raise HTTPException(
            503,
            "Could not load configuration."
        )

    return {
        "success": True,
        "settings": settings
    }


@app.post("/admin/config")
def admin_save_config(
    config: PlatformConfig,
    owner_uid: str = Depends(require_platform_owner)
):
    validate_platform_config(config)

    data = config.model_dump()

    try:
        platform_config_ref().set({
            **data,
            "updated_by": owner_uid,
            "updated_at": firestore.SERVER_TIMESTAMP
        })
    except Exception:
        raise HTTPException(
            503,
            "Configuration could not be saved."
        )

    return {
        "success": True,
        "message": "Configuration saved successfully.",
        "settings": data
    }


@app.get("/public/config")
def public_platform_config():
    try:
        settings = load_platform_config()
    except Exception:
        raise HTTPException(
            503,
            "Public configuration unavailable."
        )

    # Only expose safe public settings.
    public_fields = [
        "website_name",
        "support_email",
        "support_link",
        "currency",
        "timezone",
        "support_bot_username",
        "turnstile_site_key",
        "turnstile_enabled",
        "upi_id",
        "upi_payee_name",
        "upi_qr_url",
        "deposit_enabled",
        "min_deposit",
        "max_deposit",
        "withdrawal_enabled",
        "min_withdrawal",
        "max_withdrawal",
        "withdrawal_tax_percent",
        "withdrawal_fixed_tax",
        "daily_withdrawal_limit",
        "withdrawal_upi_enabled",
        "withdrawal_mobile_enabled",
        "withdrawal_verification_required",
        "registration_enabled",
        "maintenance_mode"
    ]

    return {
        "success": True,
        **{
            key: settings[key]
            for key in public_fields
        }
    }
    
