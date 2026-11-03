
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SwiftPay API",
    description="SwiftPay Payment Gateway Backend",
    version="1.0.0"
)

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "http://localhost:3000"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.get("/")
def home():
    return {
        "status": "success",
        "message": "Welcome to SwiftPay API",
        "version": "1.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "SwiftPay Backend"
    }
  
