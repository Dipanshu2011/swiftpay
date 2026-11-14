# SwiftPays deployment bundle

Files:
- `app.py`: FastAPI backend for Render
- `index.html`: user registration/login entry page
- `admin.html`: admin portal (Owner + permissioned Admin accounts)
- `requirements.txt`: Render dependencies

## Render
Build: `pip install -r requirements.txt`
Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`

Set existing secrets: `OWNER_UID`, `SESSION_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS` (secret file path), `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`, `TELEGRAM_LINK_SECRET`, `TURNSTILE_SECRET_KEY`.
Set `FIREBASE_STORAGE_BUCKET` to the Firebase Storage bucket name (for example `your-project-id.firebasestorage.app` or the exact bucket shown in Firebase). Enable Firebase Storage and grant the service account access.

## Cloudflare Pages
Upload `index.html` as the site entry page. Upload `admin.html` and access it at `/admin.html`. The admin page is the supplied existing dashboard file, updated for role-based navigation.

## Admin onboarding
Create each admin as a Firebase Authentication user first. Sign in to the backend as Owner, then use the owner-only API `POST /admin/manage-admins` with Firebase Owner ID token:
`{ "uid": "FIREBASE_AUTH_UID", "name": "Admin Name", "permissions": ["dashboard","users","deposits","withdrawals","reports"] }`
Allowed permissions: dashboard, users, deposits, withdrawals, wallet, reports, coupons. Only OWNER_UID is Owner. Admins cannot add/remove admins or change platform configuration.

## Important verification
This bundle has been syntax-checked locally, but it has not been deployed against your live Firebase/Render project. Verify Firebase Storage bucket setup, Firestore indexes/rules, Telegram webhook/link callback and all transaction flows in a test environment before accepting real payments. Manual UPI approval is not bank-side UTR verification; staff must verify payment in their UPI/bank app before approving.
