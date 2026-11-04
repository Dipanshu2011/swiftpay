
import os
import json
import urllib.request
import urllib.parse

import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SwiftPays API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://swiftpays.pages.dev",
        "http://localhost",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_firebase():
    if not firebase_admin._apps:
        path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not path or not os.path.isfile(path):
            raise RuntimeError("Firebase credentials not found")

        cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred)

    return firestore.client()


class TurnstileRequest(BaseModel):
    token: str


@app.get("/")
def home():
    return {
        "status": "success",
        "message": "Welcome to SwiftPays API"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "SwiftPays Backend"
    }


@app.get("/firebase-status")
def firebase_status():
    try:
        db = get_firebase()
        db.collection("_health").document("check").get(timeout=10)
        return {
            "status": "connected",
            "service": "Firebase Firestore"
        }
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Firebase connection failed"
        )


@app.post("/verify-turnstile")
def verify_turnstile(data: TurnstileRequest):
    secret = os.getenv("TURNSTILE_SECRET_KEY")

    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Turnstile is not configured"
        )

    if not data.token.strip():
        raise HTTPException(
            status_code=400,
            detail="Verification token is required"
        )

    payload = urllib.parse.urlencode({
        "secret": secret,
        "response": data.token
    }).encode()

    request = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode())

        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail="Turnstile verification failed"
            )

        if result.get("hostname") not in (
            "swiftpays.pages.dev",
            "localhost"
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid verification hostname"
            )

        return {"success": True, "message": "Verification successful"}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Verification service unavailable"
    )
        
