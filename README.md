# SwiftPays — Neon Blue Gateway Bundle

This bundle is a front-end and FastAPI backend starter for the SwiftPays wallet/payment-request workflow.

## Included files

### Cloudflare Pages (static frontend)
- `index.html` — public landing page with Login and Create Account links.
- `register.html` — registration form with Cloudflare Turnstile verification.
- `create-pin.html` — 6-digit S-PIN setup after registration.
- `login.html` — user login.
- `dashboard.html` — user dashboard, wallet balance, UPI deposit request, withdrawal request, and recent activity.
- `admin-login.html` — Firebase Authentication sign-in for the configured Owner/Admin.
- `admin-dashboard.html` — admin operations dashboard.
- `logo.png` — supplied brand image.
- `_redirects` — clean URL routes for Cloudflare Pages.

### Render (backend)
- `app.py` — FastAPI API, Firebase Authentication for admin sign-in, Firestore user/wallet/payment-request records, session validation, configuration, manual approvals, coupons, reports, and admin management.
- `requirements.txt` — Python dependencies.

## Current payment behavior — important
This bundle currently implements **manual UPI deposit review** and **manual withdrawal approval**. A user submits amount + UTR + optional screenshot; the request remains pending until an authorized admin reviews it. It does **not** connect to a bank, UPI switch, payment aggregator, or automatic payment-verification provider. Do not advertise automatic payment confirmation until a regulated/authorized provider's API and verified webhook flow are integrated and tested.

## Deploy frontend to Cloudflare Pages
1. Extract the ZIP.
2. Upload the contents of this folder as the Cloudflare Pages project root (not the enclosing folder).
3. Confirm the production hostname is `swiftpays.pages.dev`, or add your custom domain to the backend CORS allow-list in `app.py`.
4. Confirm these routes work: `/`, `/register`, `/create-pin`, `/login`, `/dashboard`, `/admin/login`, `/admin/dashboard`.

## Deploy backend to Render
1. Create a Python web service from the GitHub repository containing `app.py` and `requirements.txt`.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
4. Set the environment variables listed below.
5. Deploy, then test `https://YOUR-RENDER-SERVICE/health`.

## Required Render environment variables
- `SESSION_SECRET` — long random secret, at least 32 characters. Use a unique value; never share it or commit it.
- `OWNER_UID` — Firebase Authentication UID of the single platform owner.
- `GOOGLE_APPLICATION_CREDENTIALS` — absolute path to the Firebase service-account JSON file on Render. Upload it as a Render secret file and set this variable to its mounted path.
- `TURNSTILE_SECRET_KEY` — Cloudflare Turnstile secret key. Keep it server-side only.
- `TELEGRAM_BOT_TOKEN` — optional, used only by Telegram OTP/link features that are enabled in the backend.
- `TELEGRAM_ALERT_BOT_TOKEN` — optional separate bot token for user alerts.

The admin pages use Firebase Web Authentication configuration embedded in the frontend. The Firebase API key is a public web config value, not a service-account secret. Enable the Firebase Authentication provider used by the admin login and restrict authorized admin accounts in the backend.

## Required Firebase / Cloudflare setup
1. Create a Firebase project and enable Cloud Firestore.
2. Create a Firebase service account; store its JSON securely as a Render secret file. Never upload it to the public Pages site or GitHub.
3. Enable Firebase Authentication (Email/Password) for the Owner account. Set `OWNER_UID` to that account's UID.
4. Add Firestore indexes if Firebase reports a missing-index error for a query.
5. Create a Cloudflare Turnstile widget for `swiftpays.pages.dev`; set the widget's Site Key in the Firestore `siteSettings/platform` document as `turnstile_site_key` and keep `turnstile_enabled: true`. Set the matching Secret Key in Render as `TURNSTILE_SECRET_KEY`.
6. Set the UPI ID, payee name, QR image URL, deposit/withdrawal limits and taxes in the Owner dashboard configuration.

## Security and go-live checklist
- Use HTTPS for both Pages and Render.
- Keep Firebase service-account JSON, `SESSION_SECRET`, Turnstile secret and Telegram bot tokens private.
- Add your final frontend hostname to the CORS allow-list in `app.py` before using a custom domain.
- Use a unique high-entropy `SESSION_SECRET`.
- Test registration, expired setup tokens, login, logout, deposit duplicate-UTR handling, withdrawal balance reservation/refund, admin approval/rejection and permissions with test accounts.
- Check Render logs and browser console for errors.
- Do not accept real customer funds until a real payment provider, webhook signature verification, reconciliation and refund/dispute handling are integrated and independently tested.

## Notes
- The Python file passes a syntax compilation check.
- This is not a guarantee that a live deployment is error-free: Firebase credentials, Firestore rules/indexes, Turnstile keys, Render environment variables, CORS and provider integration must be tested in the deployed environment.
- Never paste secrets into chat or commit them to GitHub.
