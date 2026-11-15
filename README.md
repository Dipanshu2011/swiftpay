# SwiftPays deployment bundle

Upload all HTML, `_redirects`, and `logo.png` to the Cloudflare Pages root.
- `index.html`: device verification / registration entry
- `register.html`: create account
- `login.html`: user login
- `create-pin.html`: S-PIN setup
- `admin-login.html`: Owner/Admin login
- `admin-dashboard.html`: protected dashboard

Render root files: `app.py`, `requirements.txt`.
Build: `pip install -r requirements.txt`
Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`

Keep existing Render secrets and Firebase service-account secret file unchanged.
Admin sign-in starts only at `/admin-login.html`; successful login opens `/admin-dashboard.html`.
The dashboard does not prompt for credentials and redirects to login if its 24-hour device session is missing or invalid.

Syntax checks pass locally; verify live Firebase/Render integration and test all payment flows before accepting real payments. Manual UPI approval is not automatic bank-side verification.
