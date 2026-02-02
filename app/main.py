"""
Fortress - Secure Software Supply Chain Artifact Vault
Main FastAPI Application
"""
import os
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlmodel import Session, select

from app.models import init_db, User, Artifact, engine
from app.auth import authenticate_user, verify_totp, is_session_valid, get_current_totp

# --- App Setup ---
app = FastAPI(title="Fortress", description="Secure Artifact Vault")

# Session middleware for cookie-based auth (15 min timeout handled in auth logic)
app.add_middleware(SessionMiddleware, secret_key=os.urandom(32).hex(), max_age=900)

# Static files and templates
BASE_DIR = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Ensure required directories exist
(BASE_DIR / "storage").mkdir(exist_ok=True)
(BASE_DIR / "keys").mkdir(exist_ok=True)

# --- Startup Event ---
@app.on_event("startup")
def on_startup():
    init_db()

# --- Auth Dependency ---
def get_current_user(request: Request):
    """Get current authenticated user from session."""
    user_id = request.session.get("user_id")
    session_created = request.session.get("session_created")
    
    if not user_id or not session_created:
        return None
    
    created_at = datetime.fromisoformat(session_created)
    if not is_session_valid(created_at):
        request.session.clear()
        return None
    
    with Session(engine) as db:
        return db.get(User, user_id)

# --- Basic Routes ---
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Step 1: Verify username and password."""
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials"
        })
    
    # Store user_id temporarily for OTP verification
    request.session["pending_user_id"] = user.id
    request.session["pending_username"] = user.username
    
    # Debug: print TOTP (remove in production)
    print(f"[DEBUG] TOTP for {user.username}: {get_current_totp(user.totp_secret)}")
    
    return templates.TemplateResponse("otp.html", {
        "request": request,
        "username": user.username
    })

@app.post("/verify-otp")
async def verify_otp_route(request: Request, otp_code: str = Form(...)):
    """Step 2: Verify TOTP code."""
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/", status_code=302)
    
    with Session(engine) as db:
        user = db.get(User, pending_user_id)
        if not user or not verify_totp(user.totp_secret, otp_code):
            return templates.TemplateResponse("otp.html", {
                "request": request,
                "username": request.session.get("pending_username"),
                "error": "Invalid OTP code"
            })
        
        # Clear pending and set authenticated session
        request.session.pop("pending_user_id", None)
        request.session.pop("pending_username", None)
        request.session["user_id"] = user.id
        request.session["session_created"] = datetime.utcnow().isoformat()
        
        return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/dashboard")
async def dashboard(request: Request):
    """Main dashboard - requires authentication."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    
    with Session(engine) as db:
        artifacts = db.exec(select(Artifact)).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "artifacts": artifacts
    })

@app.get("/logout")
async def logout(request: Request):
    """Clear session and logout."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

# --- Upload Endpoint ---
from pydantic import BaseModel
import base64

class UploadPayload(BaseModel):
    filename: str
    file_b64: str
    signature: str
    hash: str

@app.post("/upload")
async def upload_artifact(request: Request, payload: UploadPayload):
    """
    Receive artifact from Developer CLI.
    Verifies signature, checks integrity, encrypts, and stores.
    """
    from app.crypto_utils import CryptoUtils
    from app.models import UserRole, ArtifactStatus
    
    user = get_current_user(request)
    if not user or user.role != UserRole.DEVELOPER:
        return {"error": "Unauthorized. Developer role required."}
    
    # Decode file content
    try:
        file_content = base64.b64decode(payload.file_b64)
        signature = base64.b64decode(payload.signature)
    except Exception:
        return {"error": "Invalid Base64 encoding"}
    
    # Verify integrity: re-calculate hash
    import hashlib
    calculated_hash = hashlib.sha256(file_content).hexdigest()
    if calculated_hash != payload.hash:
        return {"error": "Integrity check failed. Hash mismatch."}
    
    # Verify signature using developer's public key
    if not user.public_key_path:
        return {"error": "No public key registered for this user"}
    
    public_key = CryptoUtils.load_public_key(user.public_key_path)
    if not CryptoUtils.verify_signature(public_key, payload.hash.encode(), signature):
        return {"error": "Signature verification failed"}
    
    # Encrypt and save
    aes_key = CryptoUtils.generate_aes_key()
    nonce, ciphertext = CryptoUtils.encrypt_data(file_content, aes_key)
    
    storage_filename = f"{payload.hash[:16]}_{payload.filename}.enc"
    storage_path = BASE_DIR / "storage" / storage_filename
    
    with open(storage_path, "wb") as f:
        f.write(nonce + aes_key + ciphertext)  # Store nonce + key + data
    
    # Save to DB
    with Session(engine) as db:
        artifact = Artifact(
            filename=payload.filename,
            file_hash=payload.hash,
            signature=payload.signature,
            storage_path=str(storage_path),
            uploader_id=user.id,
            status=ArtifactStatus.PENDING
        )
        db.add(artifact)
        db.commit()
    
    return {"status": "success", "message": "Artifact uploaded and encrypted"}
