"""SwiftPays Telegram bot (stdlib-only polling version).

Required environment variables:
  TELEGRAM_BOT_TOKEN   BotFather token (keep secret)
  SWIFTPAYS_API_URL    https://swiftpay-api-6azu.onrender.com
  TELEGRAM_LINK_SECRET Same secret configured on the SwiftPays backend

Run: python SwiftPaysBot.py
"""

import json
import os
import time
import urllib.parse
import urllib.request

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
API_BASE = os.getenv("SWIFTPAYS_API_URL", "https://swiftpay-api-6azu.onrender.com").rstrip("/")
LINK_SECRET = os.getenv("TELEGRAM_LINK_SECRET", "").strip()
BOT_API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def http_json(url, data=None, headers=None, timeout=35):
    body = None if data is None else urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def send_message(chat_id, text):
    try:
        result = http_json(BOT_API + "/sendMessage", {
            "chat_id": str(chat_id), "text": text, "disable_web_page_preview": "true"
        })
        return bool(result.get("ok"))
    except Exception as exc:
        print("sendMessage error:", exc)
        return False


def account_status(telegram_user_id):
    if not LINK_SECRET:
        return None, "Telegram link secret is not configured."
    try:
        result = http_json(
            API_BASE + "/telegram/status",
            {"telegram_user_id": str(telegram_user_id)},
            {"X-Telegram-Link-Secret": LINK_SECRET},
        )
        return result, None
    except Exception as exc:
        print("status API error:", exc)
        return None, "SwiftPays account status is temporarily unavailable. Please try again later."


def start_text(first_name):
    name = first_name or "there"
    return (
        f"Hello {name}! Welcome to SwiftPays.\n\n"
        "I can help you check your Telegram connection and receive account alerts.\n\n"
        "Commands:\n"
        "/status - Check Telegram account connection\n"
        "/help - Show help\n\n"
        "To connect your account, open SwiftPays and use Settings → Telegram Alerts. "
        "Never share your password, OTP, or Telegram bot token with anyone."
    )


def handle_message(message):
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return

    text = (message.get("text") or "").strip()
    command = text.split()[0].split("@", 1)[0].lower() if text else ""

    if command in ("/start", "/help"):
        send_message(chat_id, start_text(sender.get("first_name", "")))
        return

    if command == "/status":
        result, error = account_status(sender.get("id", chat_id))
        if error:
            send_message(chat_id, error)
        elif not result.get("linked"):
            send_message(
                chat_id,
                "Your Telegram account is not linked to SwiftPays yet.\n\n"
                "Open SwiftPays → Settings → Telegram Alerts → Connect Telegram, "
                "then follow the secure linking steps."
            )
        else:
            send_message(
                chat_id,
                "SwiftPays Telegram connection: ACTIVE ✅\n"
                f"Account: {result.get('operator') or 'SwiftPays user'}\n"
                f"Mobile: {result.get('mobile_masked') or 'Hidden'}\n"
                f"Account status: {result.get('account_status') or 'Unknown'}"
            )
        return

    send_message(chat_id, "I didn't recognize that command. Use /help to see available commands.")


def main():
    if not BOT_TOKEN:
        raise SystemExit("Missing TELEGRAM_BOT_TOKEN environment variable.")
    if not LINK_SECRET:
        print("Warning: TELEGRAM_LINK_SECRET is missing; /status will not work.")

    print("SwiftPaysBot is running with long polling.")
    offset = None
    while True:
        try:
            params = {"timeout": 25}
            if offset is not None:
                params["offset"] = offset
            query = urllib.parse.urlencode(params)
            updates = http_json(BOT_API + "/getUpdates?" + query, timeout=35)
            if not updates.get("ok"):
                time.sleep(3)
                continue
            for update in updates.get("result", []):
                offset = update["update_id"] + 1
                message = update.get("message") or update.get("edited_message")
                if message:
                    handle_message(message)
        except KeyboardInterrupt:
            print("SwiftPaysBot stopped.")
            break
        except Exception as exc:
            print("Polling error:", exc)
            time.sleep(3)


if __name__ == "__main__":
    main()
