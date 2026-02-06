"""
Fortress - Secure Software Supply Chain Artifact Vault
Main FastAPI Application
"""
import os
import base64
import hashlib
import qrcode
from io import BytesIO
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlmodel import Session, select
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization as crypto_serialization

from app.models import init_db, User, Artifact, engine, UserRole, ArtifactStatus
from app.auth import authenticate_user, verify_totp, is_session_valid, get_current_totp, get_qr_code_data, hash_password
from app.crypto_utils import CryptoUtils

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

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    """
    Self-Registration endpoint.
    Creates an INACTIVE user with 'developer' role.
    Requires Admin approval to activate.
    """
    with Session(engine) as db:
        existing = db.exec(select(User).where(User.username == username)).first()
        if existing:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Username already exists"
            })
        
        user = User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.DEVELOPER, # Force developer role
            is_active=False,         # Inactive by default
            mfa_secret=None
        )
        db.add(user)
        db.commit()
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "success": "Registration successful! Your account is pending Admin approval."
    })

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Step 1: Verify username and password."""
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials"
        })
    
    
    # Check if user is active
    if not user.is_active:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Account inactive. Please contact your Manager."
        })
    
    # Check if user needs to setup MFA
    if not user.mfa_secret:
        # Store pending user ID and redirect to setup
        request.session["pending_user_id"] = user.id
        request.session["pending_username"] = user.username
        return RedirectResponse(url="/setup-mfa", status_code=302)

    # Store user_id temporarily for OTP verification
    request.session["pending_user_id"] = user.id
    request.session["pending_username"] = user.username
    
    # Debug: print TOTP (remove in production)
    if user.mfa_secret:
        print(f"[DEBUG] TOTP for {user.username}: {get_current_totp(user.mfa_secret)}")
    
    return templates.TemplateResponse("otp.html", {
        "request": request,
        "username": user.username
    })

@app.get("/setup-mfa")
async def setup_mfa_page(request: Request):
    """Show MFA setup page with QR code."""
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/", status_code=302)
    
    with Session(engine) as db:
        user = db.get(User, pending_user_id)
        if not user:
            return RedirectResponse(url="/", status_code=302)
        
        # Check if already setup (shouldn't be here)
        if user.mfa_secret:
            return RedirectResponse(url="/", status_code=302) # Should go to verify-otp logically but simpler to redirect home
        
        # Generate QR data
        secret, qr_b64 = get_qr_code_data(user.username)
        
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request,
            "qr_b64": qr_b64,
            "secret": secret
        })

@app.post("/setup-mfa")
async def setup_mfa_submit(request: Request, secret: str = Form(...), otp_code: str = Form(...)):
    """Verify code and save MFA secret."""
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/", status_code=302)
    
    # Verify the code against the PROPOSED secret
    if not verify_totp(secret, otp_code):
         # Regenerate generic QR (or pass back the same if we could, but simpler to error)
         # For UX, we re-render the page. Ideally we should re-use secret but 
         # since we didn't save it, we'll just error out or re-render.
         # Re-rendering needs new QR though.
         # Let's simple re-render with error.
         
         with Session(engine) as db:
             user = db.get(User, pending_user_id)
             secret_new, qr_b64 = get_qr_code_data(user.username)
             
             return templates.TemplateResponse("mfa_setup.html", {
                "request": request,
                "qr_b64": qr_b64,
                "secret": secret_new,
                "error": "Invalid code. Please scan the new QR code."
            })

    # Code valid! Save secret to DB.
    with Session(engine) as db:
        user = db.get(User, pending_user_id)
        if not user:
             return RedirectResponse(url="/", status_code=302)
        
        user.mfa_secret = secret
        db.add(user)
        db.commit()
    
    # Log them in fully
    request.session.pop("pending_user_id", None)
    request.session.pop("pending_username", None)
    request.session["user_id"] = pending_user_id
    request.session["session_created"] = datetime.utcnow().isoformat()
    
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/verify-otp")
async def verify_otp_route(request: Request, otp_code: str = Form(...)):
    """Step 2: Verify TOTP code."""
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/", status_code=302)
    
    with Session(engine) as db:
        user = db.get(User, pending_user_id)
        if not user or not user.mfa_secret or not verify_totp(user.mfa_secret, otp_code):
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
        # Access Control:
        # Developers: See ONLY their own artifacts
        # Managers/Auditors: See ALL artifacts
        if user.role == UserRole.DEVELOPER:
            artifacts = db.exec(select(Artifact).where(Artifact.uploader_id == user.id)).all()
        else:
            artifacts = db.exec(select(Artifact)).all()
        
        # For Managers: Fetch inactive users
        inactive_users = []
        if user.role == UserRole.MANAGER:
            inactive_users = db.exec(select(User).where(User.is_active == False)).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "artifacts": artifacts,
        "inactive_users": inactive_users
    })

@app.get("/logout")
async def logout(request: Request):
    """Clear session and logout."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

# --- Key Registration Models ---
class KeyRegistrationPayload(BaseModel):
    username: str
    public_key: str  # PEM format
    signature: str   # Base64 encoded PoP signature

# --- Key Registration Endpoint (TOFU) ---
@app.post("/register-key")
async def register_key(payload: KeyRegistrationPayload):
    """
    Trust-On-First-Use (TOFU) Key Registration.
    Verifies Proof-of-Possession (PoP) before trusting the key.
    """
    with Session(engine) as db:
        user = db.exec(select(User).where(User.username == payload.username)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Security Check: Role must be Developer
        if user.role != UserRole.DEVELOPER:
             raise HTTPException(status_code=403, detail="Only developers can register keys")

        # Security Check: Verify Proof-of-Possession
        try:
            # Load the candidate public key
            public_key = crypto_serialization.load_pem_public_key(payload.public_key.encode('utf-8'))
            
            # Verify the signature (User signed their own username)
            signature_bytes = base64.b64decode(payload.signature)
            if not CryptoUtils.verify_signature(public_key, payload.username.encode('utf-8'), signature_bytes):
                raise HTTPException(status_code=400, detail="Proof-of-Possession failed: Invalid signature")
                
        except Exception as e:
             # print(f"DEBUG: {e}") 
             raise HTTPException(status_code=400, detail=f"Invalid Key or Signature format: {str(e)}")

        # TOFU: Trust and Save
        # 1. Save Public Key to disk
        keys_dir = Path("keys")
        keys_dir.mkdir(exist_ok=True)
        key_filename = f"{user.username}_public.pem"
        key_path = keys_dir / key_filename
        
        with open(key_path, "wb") as f:
            f.write(payload.public_key.encode('utf-8'))
            
        # 2. Update User Record
        user.public_key_path = str(key_path.absolute())
        db.add(user)
        db.commit()
        
        return {"status": "success", "message": f"Key registered for {user.username}"}

# --- Upload Endpoint ---
class UploadPayload(BaseModel):
    filename: str
    username: str  # Added for signature-based auth
    file_b64: str
    signature: str
    hash: str

@app.post("/upload")
async def upload_artifact(request: Request, payload: UploadPayload):
    """
    Receive artifact from Developer CLI.
    Verifies signature, checks integrity, encrypts, and stores.
    Authentication is done via RSA Signature verification (API Key style).
    """
    
    # Lookup user by username provided in payload
    with Session(engine) as db:
        user = db.exec(select(User).where(User.username == payload.username)).first()
    
    if not user:
        return {"error": "User not found"}
        
    if user.role != UserRole.DEVELOPER:
        return {"error": "Unauthorized. Developer role required."}
    
    # Decode file content
    try:
        file_content = base64.b64decode(payload.file_b64)
        signature = base64.b64decode(payload.signature)
    except Exception:
        return {"error": "Invalid Base64 encoding"}
    
    # Verify integrity: re-calculate hash
    calculated_hash = hashlib.sha256(file_content).hexdigest()
    if calculated_hash != payload.hash:
        return {"error": "Integrity check failed. Hash mismatch."}
    
    # Verify signature using developer's public key
    if not user.public_key_path:
        return {"error": "No public key registered for this user"}
    
    print(f"[DEBUG] Verifying upload for user: {user.username}")
    print(f"[DEBUG] Public Key Path: {user.public_key_path}")
    print(f"[DEBUG] Payload Hash: {payload.hash}")
    
    try:
        public_key = CryptoUtils.load_public_key(user.public_key_path)
        if not CryptoUtils.verify_signature(public_key, payload.hash.encode(), signature):
            print(f"[DEBUG] Signature verification FAILED")
            # --- DEBUG BLOCK START ---
            # dump keys to see if they match pair
            print(f"[DEBUG] Public Key Modulus: {public_key.public_numbers().n}")
            # we can't see private key here obviously.
            # --- DEBUG BLOCK END ---
            return {"error": "Signature verification failed"}
        print(f"[DEBUG] Signature verification SUCCESS")
    except Exception as e:
        print(f"[DEBUG] Error loading verify key: {e}")
        return {"error": f"Internal verification error: {e}"}
    
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

# --- Approve Endpoint ---
@app.post("/approve/{artifact_id}")
async def approve_artifact(request: Request, artifact_id: int):
    """
    Approve an artifact (Manager only).
    Changes status from PENDING to APPROVED.
    """
    
    user = get_current_user(request)
    if not user or user.role != UserRole.MANAGER:
        return {"error": "Unauthorized. Manager role required."}
    
    with Session(engine) as db:
        artifact = db.get(Artifact, artifact_id)
        if not artifact:
            return {"error": "Artifact not found"}
        
        artifact.status = ArtifactStatus.APPROVED
        artifact.approved_by = user.id
        artifact.approved_at = datetime.utcnow()
        db.add(artifact)
        db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=302)

# --- QR Code Endpoint ---
@app.get("/qr/{artifact_id}")
async def generate_qr(request: Request, artifact_id: int):
    """Generate QR code containing artifact hash."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    
    with Session(engine) as db:
        artifact = db.get(Artifact, artifact_id)
        if not artifact:
            return {"error": "Artifact not found"}
        
        # Generate QR code with hash
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(artifact.file_hash)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Return as image
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return StreamingResponse(buffer, media_type="image/png")
    
@app.post("/approve-user/{user_id}")
async def approve_user(request: Request, user_id: int):
    """
    Approve an inactive user (Manager only).
    """
    user = get_current_user(request)
    if not user or user.role != UserRole.MANAGER:
        return RedirectResponse(url="/dashboard", status_code=302)
    
    with Session(engine) as db:
        user_to_approve = db.get(User, user_id)
        if not user_to_approve:
            return RedirectResponse(url="/dashboard", status_code=302)
            
        user_to_approve.is_active = True
        db.add(user_to_approve)
        db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=302)


