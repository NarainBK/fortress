"""
Fortress - Test Data Setup Script
Creates test users and generates RSA keys for testing.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path
from app.models import init_db, User, engine
from app.auth import hash_password, generate_mfa_secret, get_totp_uri
from app.crypto_utils import CryptoUtils
from sqlmodel import Session

# Ensure directories exist
BASE_DIR = Path(__file__).parent
(BASE_DIR / "keys").mkdir(exist_ok=True)
(BASE_DIR / "storage").mkdir(exist_ok=True)

def setup():
    print("=" * 50)
    print("🏰 Fortress - Test Data Setup")
    print("=" * 50)
    
    # Initialize database
    print("\n[1/4] Initializing database...")
    init_db()
    print("      ✅ Database created: fortress.db")
    
    # Generate Developer keys
    print("\n[2/4] Generating Developer RSA keys...")
    dev_private_key, dev_public_key = CryptoUtils.generate_rsa_key_pair()
    
    dev_private_path = BASE_DIR / "keys" / "dev_private.pem"
    dev_public_path = BASE_DIR / "keys" / "dev_public.pem"
    
    CryptoUtils.save_key_to_file(dev_private_key, str(dev_private_path), is_private=True)
    CryptoUtils.save_key_to_file(dev_public_key, str(dev_public_path), is_private=False)
    print(f"      ✅ Private key: {dev_private_path}")
    print(f"      ✅ Public key: {dev_public_path}")
    
    # Create test users
    print("\n[3/4] Creating test users...")
    
    # dev_totp_secret = generate_mfa_secret()
    # mgr_totp_secret = generate_mfa_secret()
    # aud_totp_secret = generate_mfa_secret()
    
    with Session(engine) as session:
        # Check if users already exist
        existing = session.get(User, 1)
        if existing:
            print("      ⚠️  Users already exist. Skipping...")
        else:
            developer = User(
                username="developer",
                password_hash=hash_password("dev123"),
                role="developer",
                mfa_secret=None, # User will setup MFA manually
                public_key_path=str(dev_public_path)
            )
            
            manager = User(
                username="manager",
                password_hash=hash_password("mgr123"),
                role="manager",
                mfa_secret=None, # User will setup MFA manually
                public_key_path=None
            )
            
            auditor = User(
                username="auditor",
                password_hash=hash_password("aud123"),
                role="auditor",
                mfa_secret=None, # User will setup MFA manually
                public_key_path=None
            )
            
            session.add(developer)
            session.add(manager)
            session.add(auditor)
            session.commit()
            print("      ✅ Created user: developer (password: dev123)")
            print("      ✅ Created user: manager (password: mgr123)")
            print("      ✅ Created user: auditor (password: aud123)")
    
    # Print TOTP info
    print("\n[4/4] Accounts Created:")
    print("-" * 50)
    print("Usernames: developer, manager, auditor")
    print("Passwords: dev123, mgr123, aud123")
    print("-" * 50)
    print("⚠️  MFA is NOT configured. You will be prompted to setup MFA on first login.")
    
    print("\n" + "=" * 50)
    print("✅ Setup complete!")
    print("=" * 50)
    print("\n🚀 To run the server:")
    print("   uvicorn app.main:app --reload")
    print("\n🌐 Then visit: http://localhost:8000")
    print("\n📤 To upload an artifact (as developer):")
    print(f"   python client_upload.py <file> keys/dev_private.pem")

if __name__ == "__main__":
    setup()
