import os
import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SwiftPays API",
    version="1.0.0"
)

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "https://swiftpays.pages.dev"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

def get_firebase():
    if not firebase_admin._apps:
        path = os.getenv(
            "GOOGLE_APPLICATION_CREDENTIALS"
        )
        if not path or not os.path.isfile(path):
            raise RuntimeError("Firebase credentials not found")

        cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred)

    return firestore.client()


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
        db.collection("_health").document("check").get(
            timeout=10
        )
        return {
            "status": "connected",
            "service": "Firebase Firestore"
        }
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Firebase connection failed. Check server configuration."
    )
