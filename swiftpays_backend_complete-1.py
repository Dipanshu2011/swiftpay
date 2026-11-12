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

    # Deposit tax (deducted from credited amount)
    deposit_tax_percent: float = Field(default=0, ge=0, le=100)
    deposit_fixed_tax: float = Field(default=0, ge=0, le=10000000)

    # User Telegram alert bot public configuration (token stays in Render env)
    alert_bot_username: str = Field(default="", max_length=80)
    user_telegram_alerts_enabled: bool = True

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
        "alert_bot_username",
        "user_telegram_alerts_enabled",
        "turnstile_site_key",
        "turnstile_enabled",
        "upi_id",
        "upi_payee_name",
        "upi_qr_url",
        "deposit_enabled",
        "min_deposit",
        "max_deposit",
        "deposit_tax_percent",
        "deposit_fixed_tax",
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
    

class TelegramStatusRequest(BaseModel):
    telegram_user_id: str


@app.post("/telegram/status")
def telegram_status(
    data: TelegramStatusRequest,
    x_telegram_link_secret: str = Header(default="")
):
    supplied = os.getenv("TELEGRAM_LINK_SECRET", "")

    if not supplied or not hmac.compare_digest(
        supplied, x_telegram_link_secret
    ):
        raise HTTPException(401, "Unauthorized Telegram bot callback.")

    uid = str(data.telegram_user_id).strip()

    if not uid.isdigit():
        raise HTTPException(400, "Invalid Telegram user ID.")

    db = get_firebase()

    link = db.collection("telegram_users").document(uid).get()

    if not link.exists:
        return {
            "status": "success",
            "registered": False,
            "linked": False
        }

    link_data = link.to_dict() or {}
    mobile = str(link_data.get("mobile", "")).strip()

    if not mobile:
        raise HTTPException(404, "Linked account not found.")

    user_snap = db.collection("users").document("m_" + mobile).get()

    if not user_snap.exists:
        raise HTTPException(404, "Linked account record not found.")

    user = user_snap.to_dict() or {}

    if str(user.get("telegram_user_id", "")) != uid:
        raise HTTPException(403, "Telegram account mismatch.")

    return {
        "status": "success",
        "registered": True,
        "linked": True,
        "operator": user.get("name", ""),
        "user_id": user.get("user_id", ""),
        "telegram_id": uid,
        "mobile_masked": mobile[:2] + "******" + mobile[-2:],
        "wallet_balance": round(int(user.get("balance_paise", 0)) / 100, 2),
        "keeper_balance": round(
            int(user.get("keeper_balance_paise", 0)) / 100, 2
        ),
        "account_status": user.get("status", "active")
    }
    


# ============================================================
# SWIFTPAYS COMPLETE PAYMENT / WALLET / COUPON API EXTENSION
# User sessions are the custom HMAC sessions issued by /auth/login.
# Admin routes continue to require Firebase Owner authentication.
# ============================================================

from typing import Literal

class DepositCreateRequest(BaseModel):
    amount_rupees: float = Field(gt=0, le=10000000)
    utr: str = Field(min_length=6, max_length=40)

class WithdrawalCreateRequest(BaseModel):
    amount_rupees: float = Field(gt=0, le=10000000)
    method: Literal["upi", "mobile"] = "upi"
    payout_address: str = Field(min_length=4, max_length=160)

class UserTelegramAlertRequest(BaseModel):
    enabled: bool

class AdminDecisionRequest(BaseModel):
    reason: str = Field(default="", max_length=250)

class CouponCreateRequest(BaseModel):
    code: str = Field(min_length=3, max_length=32)
    reward_type: Literal["fixed", "percent"] = "fixed"
    reward_value: float = Field(gt=0, le=1000000)
    max_uses: int = Field(default=1, ge=1, le=1000000)
    per_user_limit: int = Field(default=1, ge=1, le=100)
    expiry: str = Field(default="", max_length=40)
    min_deposit_rupees: float = Field(default=0, ge=0, le=10000000)
    status: Literal["active", "disabled"] = "active"

class CouponRedeemRequest(BaseModel):
    code: str = Field(min_length=3, max_length=32)

def require_user_session(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "User login required.")
    token = authorization[7:].strip()
    secret = os.getenv("SESSION_SECRET", "")
    if not secret:
        raise HTTPException(503, "SESSION_SECRET is not configured.")
    try:
        nonce, payload_hex, supplied_sig = token.split(".", 2)
        body = nonce + "." + payload_hex
        expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, supplied_sig):
            raise ValueError("signature")
        payload = json.loads(bytes.fromhex(payload_hex).decode())
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        user_id = str(payload.get("sub", "")).strip()
        if not user_id:
            raise ValueError("subject")
    except Exception:
        raise HTTPException(401, "Invalid or expired user session.")
    db = get_firebase()
    ref = _find_user_ref(db, user_id)
    snap = ref.get()
    user = snap.to_dict() or {}
    if user.get("status") != "active":
        raise HTTPException(403, "Your account is not active.")
    return {"user_id": user_id, "ref": ref, "data": user}

def _paise(rupees):
    return int(round(float(rupees) * 100))

def _rupees(paise):
    return round(int(paise or 0) / 100, 2)

def _safe_iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else (value or "")

def _send_user_alert(user, message):
    if not user.get("telegram_alerts_enabled", True):
        return
    chat_id = str(user.get("telegram_alert_chat_id") or user.get("telegram_user_id") or "").strip()
    token = os.getenv("TELEGRAM_ALERT_BOT_TOKEN", "").strip()
    if not chat_id or not token:
        return
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode())
        if not result.get("ok"):
            raise RuntimeError("Telegram rejected message")
    except Exception:
        # Payment state must not be rolled back just because Telegram is unavailable.
        pass

def _get_settings():
    return load_platform_config()

def _make_ledger(db, user_id, entry_type, amount_paise, old_balance, new_balance, reason, ref_id=""):
    db.collection("wallet_ledger").add({
        "user_id": user_id,
        "type": entry_type,
        "amount_paise": int(amount_paise),
        "old_balance_paise": int(old_balance),
        "new_balance_paise": int(new_balance),
        "reason": reason[:250],
        "reference_id": ref_id,
        "created_at": firestore.SERVER_TIMESTAMP
    })

@app.post("/user/deposits")
def user_create_deposit(data: DepositCreateRequest, session=Depends(require_user_session)):
    db = get_firebase()
    settings = _get_settings()
    amount = _paise(data.amount_rupees)
    if not settings.get("deposit_enabled", True):
        raise HTTPException(403, "Deposits are currently disabled.")
    if amount < _paise(settings.get("min_deposit", 10)) or amount > _paise(settings.get("max_deposit", 10000)):
        raise HTTPException(400, "Deposit amount is outside the allowed limits.")
    utr = re.sub(r"\s+", "", data.utr).upper()
    duplicate = list(db.collection("deposits").where("utr", "==", utr).limit(1).stream())
    if duplicate:
        raise HTTPException(409, "This UTR has already been submitted.")
    ref = db.collection("deposits").document()
    ref.set({
        "deposit_id": ref.id, "user_id": session["user_id"],
        "mobile": session["data"].get("mobile", ""),
        "amount_paise": amount, "utr": utr, "status": "pending",
        "created_at": firestore.SERVER_TIMESTAMP
    })
    _send_user_alert(session["data"], f"🧾 SwiftPays Deposit Submitted\nAmount: ₹{_rupees(amount):.2f}\nUTR: {utr}\nStatus: Pending review")
    return {"success": True, "deposit_id": ref.id, "status": "pending"}

@app.post("/user/withdrawals")
def user_create_withdrawal(data: WithdrawalCreateRequest, session=Depends(require_user_session)):
    db = get_firebase()
    settings = _get_settings()
    amount = _paise(data.amount_rupees)
    if not settings.get("withdrawal_enabled", True):
        raise HTTPException(403, "Withdrawals are currently disabled.")
    if amount < _paise(settings.get("min_withdrawal", 100)) or amount > _paise(settings.get("max_withdrawal", 10000)):
        raise HTTPException(400, "Withdrawal amount is outside the allowed limits.")
    if data.method == "upi" and not settings.get("withdrawal_upi_enabled", True):
        raise HTTPException(400, "UPI withdrawals are disabled.")
    if data.method == "mobile" and not settings.get("withdrawal_mobile_enabled", False):
        raise HTTPException(400, "Mobile withdrawals are disabled.")
    tax = int(round(amount * float(settings.get("withdrawal_tax_percent", 0)) / 100))
    tax += _paise(settings.get("withdrawal_fixed_tax", 0))
    if tax >= amount:
        raise HTTPException(400, "Withdrawal tax must be lower than the requested amount.")
    net = amount - tax
    ref = db.collection("withdrawals").document()
    user_ref = session["ref"]
    transaction = db.transaction()

    @firestore.transactional
    def reserve(tx):
        snap = user_ref.get(transaction=tx)
        user = snap.to_dict() or {}
        balance = int(user.get("balance_paise", 0) or 0)
        if balance < amount:
            raise HTTPException(400, "Insufficient wallet balance.")
        new_balance = balance - amount
        tx.update(user_ref, {"balance_paise": new_balance, "balance_updated_at": firestore.SERVER_TIMESTAMP})
        tx.set(ref, {
            "withdrawal_id": ref.id, "user_id": session["user_id"],
            "mobile": user.get("mobile", ""), "amount_paise": amount,
            "tax_paise": tax, "net_amount_paise": net, "method": data.method,
            "payout_address": data.payout_address.strip(), "status": "pending",
            "created_at": firestore.SERVER_TIMESTAMP, "reserved": True
        })
        ledger_ref = db.collection("wallet_ledger").document()
        tx.set(ledger_ref, {
            "user_id": session["user_id"], "type": "withdrawal_reserved",
            "amount_paise": amount, "old_balance_paise": balance,
            "new_balance_paise": new_balance, "reason": "Withdrawal request reserved",
            "reference_id": ref.id, "created_at": firestore.SERVER_TIMESTAMP
        })
    reserve(transaction)
    _send_user_alert(session["data"], f"📤 SwiftPays Withdrawal Submitted\nRequested: ₹{_rupees(amount):.2f}\nTax: ₹{_rupees(tax):.2f}\nPayout: ₹{_rupees(net):.2f}\nStatus: Pending review")
    return {"success": True, "withdrawal_id": ref.id, "status": "pending", "tax_paise": tax, "net_amount_paise": net}

@app.get("/user/telegram-alerts")
def user_get_telegram_alerts(session=Depends(require_user_session)):
    user = session["data"]
    return {
        "success": True,
        "linked": bool(user.get("telegram_user_id")),
        "alerts_enabled": bool(user.get("telegram_alerts_enabled", True)),
        "telegram_username": user.get("telegram_username") or ""
    }

@app.post("/user/telegram-alerts")
def user_set_telegram_alerts(data: UserTelegramAlertRequest, session=Depends(require_user_session)):
    session["ref"].update({
        "telegram_alerts_enabled": data.enabled,
        "telegram_alerts_updated_at": firestore.SERVER_TIMESTAMP
    })
    return {"success": True, "alerts_enabled": data.enabled}

@app.get("/admin/deposits")
def admin_get_deposits(limit: int = 50, status: str = "all", owner=Depends(require_platform_owner)):
    if limit < 1 or limit > 100:
        raise HTTPException(400, "Limit must be between 1 and 100.")
    query = get_firebase().collection("deposits").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit)
    rows = []
    for snap in query.stream():
        item = snap.to_dict() or {}
        if status != "all" and item.get("status") != status:
            continue
        item["deposit_id"] = item.get("deposit_id", snap.id)
        item["created_at"] = _safe_iso(item.get("created_at"))
        item["amount"] = _rupees(item.get("amount_paise"))
        rows.append(item)
    return {"success": True, "items": rows}

@app.post("/admin/deposits/{deposit_id}/approve")
def admin_approve_deposit(deposit_id: str, data: AdminDecisionRequest, owner=Depends(require_platform_owner)):
    db = get_firebase()
    dep_ref = db.collection("deposits").document(deposit_id)
    snap = dep_ref.get()
    if not snap.exists:
        raise HTTPException(404, "Deposit not found.")
    dep = snap.to_dict() or {}
    user_ref = _find_user_ref(db, dep["user_id"])
    settings = _get_settings()
    gross = int(dep["amount_paise"])
    tax = int(round(gross * float(settings.get("deposit_tax_percent", 0)) / 100)) + _paise(settings.get("deposit_fixed_tax", 0))
    if tax >= gross:
        raise HTTPException(400, "Deposit tax must be lower than deposit amount.")
    net = gross - tax
    tx = db.transaction()

    @firestore.transactional
    def approve(transaction):
        current = dep_ref.get(transaction=transaction)
        if not current.exists or current.to_dict().get("status") != "pending":
            raise HTTPException(409, "Deposit is already processed.")
        user_snap = user_ref.get(transaction=transaction)
        if not user_snap.exists:
            raise HTTPException(404, "User not found.")
        user = user_snap.to_dict() or {}
        old = int(user.get("balance_paise", 0) or 0)
        new = old + net
        transaction.update(user_ref, {"balance_paise": new, "balance_updated_at": firestore.SERVER_TIMESTAMP})
        transaction.update(dep_ref, {
            "status": "approved", "tax_paise": tax, "credited_paise": net,
            "reviewed_by": owner, "review_reason": data.reason,
            "reviewed_at": firestore.SERVER_TIMESTAMP
        })
        ledger_ref = db.collection("wallet_ledger").document()
        transaction.set(ledger_ref, {
            "user_id": dep["user_id"], "type": "deposit_credit",
            "amount_paise": net, "tax_paise": tax, "old_balance_paise": old,
            "new_balance_paise": new, "reason": "Deposit approved",
            "reference_id": deposit_id, "created_at": firestore.SERVER_TIMESTAMP
        })
    approve(tx)
    user_data = user_ref.get().to_dict() or {}
    _send_user_alert(user_data, f"✅ SwiftPays Deposit Approved\nDeposit: ₹{_rupees(gross):.2f}\nTax: ₹{_rupees(tax):.2f}\nCredited: ₹{_rupees(net):.2f}")
    return {"success": True, "status": "approved", "tax_paise": tax, "credited_paise": net}

@app.post("/admin/deposits/{deposit_id}/reject")
def admin_reject_deposit(deposit_id: str, data: AdminDecisionRequest, owner=Depends(require_platform_owner)):
    db = get_firebase()
    ref = db.collection("deposits").document(deposit_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(404, "Deposit not found.")
    dep = snap.to_dict() or {}
    if dep.get("status") != "pending":
        raise HTTPException(409, "Deposit is already processed.")
    ref.update({"status": "rejected", "reviewed_by": owner, "review_reason": data.reason, "reviewed_at": firestore.SERVER_TIMESTAMP})
    user = _find_user_ref(db, dep["user_id"]).get().to_dict() or {}
    _send_user_alert(user, f"❌ SwiftPays Deposit Rejected\nAmount: ₹{_rupees(dep.get('amount_paise')):.2f}\nReason: {data.reason or 'Please contact support.'}")
    return {"success": True, "status": "rejected"}

@app.get("/admin/withdrawals")
def admin_get_withdrawals(limit: int = 50, status: str = "all", owner=Depends(require_platform_owner)):
    if limit < 1 or limit > 100:
        raise HTTPException(400, "Limit must be between 1 and 100.")
    query = get_firebase().collection("withdrawals").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit)
    rows = []
    for snap in query.stream():
        item = snap.to_dict() or {}
        if status != "all" and item.get("status") != status:
            continue
        item["withdrawal_id"] = item.get("withdrawal_id", snap.id)
        item["created_at"] = _safe_iso(item.get("created_at"))
        item["amount"] = _rupees(item.get("amount_paise"))
        item["net_amount"] = _rupees(item.get("net_amount_paise"))
        rows.append(item)
    return {"success": True, "items": rows}

@app.post("/admin/withdrawals/{withdrawal_id}/approve")
def admin_approve_withdrawal(withdrawal_id: str, data: AdminDecisionRequest, owner=Depends(require_platform_owner)):
    db = get_firebase()
    ref = db.collection("withdrawals").document(withdrawal_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(404, "Withdrawal not found.")
    item = snap.to_dict() or {}
    if item.get("status") != "pending":
        raise HTTPException(409, "Withdrawal is already processed.")
    ref.update({"status": "approved", "reviewed_by": owner, "review_reason": data.reason, "reviewed_at": firestore.SERVER_TIMESTAMP})
    user = _find_user_ref(db, item["user_id"]).get().to_dict() or {}
    _send_user_alert(user, f"✅ SwiftPays Withdrawal Approved\nRequested: ₹{_rupees(item.get('amount_paise')):.2f}\nTax: ₹{_rupees(item.get('tax_paise')):.2f}\nPayout: ₹{_rupees(item.get('net_amount_paise')):.2f}\nPlease wait for payout confirmation.")
    return {"success": True, "status": "approved"}

@app.post("/admin/withdrawals/{withdrawal_id}/reject")
def admin_reject_withdrawal(withdrawal_id: str, data: AdminDecisionRequest, owner=Depends(require_platform_owner)):
    db = get_firebase()
    ref = db.collection("withdrawals").document(withdrawal_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(404, "Withdrawal not found.")
    item = snap.to_dict() or {}
    if item.get("status") != "pending":
        raise HTTPException(409, "Withdrawal is already processed.")
    user_ref = _find_user_ref(db, item["user_id"])
    tx = db.transaction()

    @firestore.transactional
    def reject(transaction):
        current = ref.get(transaction=transaction)
        if not current.exists or current.to_dict().get("status") != "pending":
            raise HTTPException(409, "Withdrawal is already processed.")
        user_snap = user_ref.get(transaction=transaction)
        user = user_snap.to_dict() or {}
        old = int(user.get("balance_paise", 0) or 0)
        refund = int(item.get("amount_paise", 0))
        new = old + refund
        transaction.update(user_ref, {"balance_paise": new, "balance_updated_at": firestore.SERVER_TIMESTAMP})
        transaction.update(ref, {"status": "rejected", "reviewed_by": owner, "review_reason": data.reason, "reviewed_at": firestore.SERVER_TIMESTAMP})
        ledger_ref = db.collection("wallet_ledger").document()
        transaction.set(ledger_ref, {"user_id": item["user_id"], "type": "withdrawal_refund",
            "amount_paise": refund, "old_balance_paise": old, "new_balance_paise": new,
            "reason": "Withdrawal rejected: " + data.reason, "reference_id": withdrawal_id,
            "created_at": firestore.SERVER_TIMESTAMP})
    reject(tx)
    user = user_ref.get().to_dict() or {}
    _send_user_alert(user, f"❌ SwiftPays Withdrawal Rejected\nAmount refunded: ₹{_rupees(item.get('amount_paise')):.2f}\nReason: {data.reason or 'Please contact support.'}")
    return {"success": True, "status": "rejected", "refunded": True}

@app.get("/admin/transactions")
def admin_get_transactions(limit: int = 100, owner=Depends(require_platform_owner)):
    if limit < 1 or limit > 200:
        raise HTTPException(400, "Limit must be between 1 and 200.")
    rows = []
    for snap in get_firebase().collection("wallet_ledger").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).stream():
        item = snap.to_dict() or {}
        item["transaction_id"] = snap.id
        item["amount"] = _rupees(item.get("amount_paise"))
        item["created_at"] = _safe_iso(item.get("created_at"))
        item["type"] = item.get("type", "")
        item["status"] = "recorded"
        rows.append(item)
    return {"success": True, "items": rows}

@app.get("/admin/wallet/ledger")
def admin_wallet_ledger(limit: int = 100, user_id: str = "", owner=Depends(require_platform_owner)):
    if limit < 1 or limit > 200:
        raise HTTPException(400, "Limit must be between 1 and 200.")
    query = get_firebase().collection("wallet_ledger").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit)
    rows = []
    for snap in query.stream():
        item = snap.to_dict() or {}
        if user_id and item.get("user_id") != user_id:
            continue
        item["entry_id"] = snap.id
        item["amount"] = _rupees(item.get("amount_paise"))
        item["old_balance"] = _rupees(item.get("old_balance_paise"))
        item["new_balance"] = _rupees(item.get("new_balance_paise"))
        item["created_at"] = _safe_iso(item.get("created_at"))
        rows.append(item)
    return {"success": True, "items": rows}

@app.get("/admin/stats")
def admin_stats(owner=Depends(require_platform_owner)):
    db = get_firebase()
    users = list(db.collection("users").stream())
    deposits = list(db.collection("deposits").stream())
    withdrawals = list(db.collection("withdrawals").stream())
    approved_deposits = [x.to_dict() or {} for x in deposits if (x.to_dict() or {}).get("status") == "approved"]
    approved_withdrawals = [x.to_dict() or {} for x in withdrawals if (x.to_dict() or {}).get("status") == "approved"]
    return {
        "success": True,
        "total_users": len(users),
        "active_users": sum(1 for x in users if (x.to_dict() or {}).get("status") == "active"),
        "blocked_users": sum(1 for x in users if (x.to_dict() or {}).get("status") == "blocked"),
        "total_deposits_paise": sum(int(x.get("amount_paise", 0)) for x in approved_deposits),
        "total_withdrawals_paise": sum(int(x.get("amount_paise", 0)) for x in approved_withdrawals),
        "total_transactions": len(list(db.collection("wallet_ledger").stream())),
        "tax_collected_paise": sum(int(x.get("tax_paise", 0)) for x in approved_deposits + approved_withdrawals)
    }

@app.post("/admin/coupons")
def admin_create_coupon(data: CouponCreateRequest, owner=Depends(require_platform_owner)):
    db = get_firebase()
    code = re.sub(r"\s+", "", data.code).upper()
    ref = db.collection("coupons").document(code)
    if ref.get().exists:
        raise HTTPException(409, "This code already exists.")
    ref.set({
        "code": code, "reward_type": data.reward_type, "reward_value": data.reward_value,
        "max_uses": data.max_uses, "per_user_limit": data.per_user_limit,
        "used_count": 0, "expiry": data.expiry, "min_deposit_paise": _paise(data.min_deposit_rupees),
        "status": data.status, "created_by": owner, "created_at": firestore.SERVER_TIMESTAMP
    })
    return {"success": True, "code": code}

@app.get("/admin/coupons")
def admin_list_coupons(owner=Depends(require_platform_owner)):
    rows = []
    for snap in get_firebase().collection("coupons").limit(300).stream():
        item = snap.to_dict() or {}
        item["code"] = snap.id
        item["min_deposit_rupees"] = _rupees(item.get("min_deposit_paise"))
        rows.append(item)
    return {"success": True, "items": rows}

@app.post("/user/coupons/redeem")
def user_redeem_coupon(data: CouponRedeemRequest, session=Depends(require_user_session)):
    db = get_firebase()
    code = re.sub(r"\s+", "", data.code).upper()
    ref = db.collection("coupons").document(code)
    claim_ref = db.collection("coupon_claims").document(session["user_id"] + "_" + code)
    tx = db.transaction()

    @firestore.transactional
    def redeem(transaction):
        coupon_snap = ref.get(transaction=transaction)
        if not coupon_snap.exists:
            raise HTTPException(404, "Invalid coupon code.")
        coupon = coupon_snap.to_dict() or {}
        if coupon.get("status") != "active":
            raise HTTPException(400, "This coupon is not active.")
        expiry = coupon.get("expiry")
        if expiry:
            try:
                if datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc) < now_utc():
                    raise HTTPException(400, "This coupon has expired.")
            except ValueError:
                raise HTTPException(400, "Coupon expiry configuration is invalid.")
        if int(coupon.get("used_count", 0)) >= int(coupon.get("max_uses", 1)):
            raise HTTPException(400, "Coupon usage limit reached.")
        if claim_ref.get(transaction=transaction).exists:
            raise HTTPException(409, "You have already redeemed this code.")
        user_snap = session["ref"].get(transaction=transaction)
        user = user_snap.to_dict() or {}
        if int(user.get("balance_paise", 0)) < int(coupon.get("min_deposit_paise", 0)):
            raise HTTPException(400, "Minimum wallet balance requirement not met.")
        if coupon.get("reward_type") == "percent":
            reward = int(int(user.get("balance_paise", 0)) * float(coupon.get("reward_value", 0)) / 100)
        else:
            reward = _paise(coupon.get("reward_value", 0))
        if reward <= 0:
            raise HTTPException(400, "Coupon reward is invalid.")
        old = int(user.get("balance_paise", 0))
        new = old + reward
        transaction.update(session["ref"], {"balance_paise": new, "balance_updated_at": firestore.SERVER_TIMESTAMP})
        transaction.update(ref, {"used_count": firestore.Increment(1)})
        transaction.set(claim_ref, {"user_id": session["user_id"], "code": code, "reward_paise": reward, "created_at": firestore.SERVER_TIMESTAMP})
        ledger_ref = db.collection("wallet_ledger").document()
        transaction.set(ledger_ref, {"user_id": session["user_id"], "type": "coupon_reward",
            "amount_paise": reward, "old_balance_paise": old, "new_balance_paise": new,
            "reason": "Coupon redeemed: " + code, "reference_id": code, "created_at": firestore.SERVER_TIMESTAMP})
        return reward
    reward = redeem(tx)
    _send_user_alert(session["data"], f"🎁 SwiftPays Coupon Redeemed\nCode: {code}\nReward: ₹{_rupees(reward):.2f}")
    return {"success": True, "reward_paise": reward, "balance_paise": int(session["ref"].get().to_dict().get("balance_paise", 0))}

@app.get("/admin/reports")
def admin_reports(owner=Depends(require_platform_owner)):
    # Aggregated from existing transaction/deposit collections; use bounded limits for operational safety.
    stats = admin_stats(owner)
    return {"success": True, "summary": stats}

