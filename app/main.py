"""
Fortress - Secure Software Supply Chain Artifact Vault
Main FastAPI Application
"""
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.models import init_db

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

# --- Basic Routes ---
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
