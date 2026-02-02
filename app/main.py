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
