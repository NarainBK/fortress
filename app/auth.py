"""
Authentication module for Fortress.
Implements bcrypt password hashing and TOTP-based MFA.
"""
import bcrypt
import pyotp
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select

from app.models import User, engine

# Session timeout (15 mins)
SESSION_TIMEOUT_MINUTES = 15

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against its hash."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_mfa_secret() -> str:
    """Generate a new TOTP secret for MFA."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str) -> str:
    """Generate a TOTP provisioning URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Fortress"
    )

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def get_current_totp(secret: str) -> str:
    """Get the current TOTP code (for testing/debugging)."""
    totp = pyotp.TOTP(secret)
    return totp.now()

def get_qr_code_data(username: str) -> tuple[str, str]:
    """
    Generate a new TOTP secret and its corresponding QR code.
    
    Args:
        username: The username to embed in the QR code.
        
    Returns:
        tuple: (secret, qr_b64)
            - secret: The base32 TOTP secret.
            - qr_b64: Base64 encoded PNG image of the QR code.
    """
    secret = generate_mfa_secret()
    uri = get_totp_uri(secret, username)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to Base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    
    return secret, qr_b64

def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    First factor authentication: Verify username and password.
    Returns User if valid, None otherwise.
    """
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).first()
        if user and verify_password(password, user.password_hash):
            return user
    return None

def is_session_valid(session_created_at: datetime) -> bool:
    """Check if session is still valid (if it is within 15 minute timeout)."""
    if session_created_at is None:
        return False
    expiry_time = session_created_at + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    return datetime.utcnow() < expiry_time

def create_user(username: str, password: str, role: str, public_key_path: str = None) -> User:
    """Create a new user with hashed password and initial MFA secret (optional)."""
    with Session(engine) as session:
        # In new flow, this might be None initially, but for helper we can generate it or leave None
        # For now, let's leave it None to respect the 'nullable for new users' rule
        user = User(
            username=username,
            password_hash=hash_password(password),
            role=role,
            mfa_secret=None,
            public_key_path=public_key_path
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
