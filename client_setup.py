"""
Fortress Client Setup Tool (Secure Key Provisioning)
Generates RSA key pair locally and registers the public key with the server via Trust-On-First-Use (TOFU).
"""
import sys
import base64
import requests
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_URL = "http://localhost:8000"

def generate_key_pair():
    """Generate RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()

def save_key(key, path, is_private=False):
    """Save key to file."""
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    with open(path, "wb") as f:
        f.write(pem)

def sign_data(private_key, data: str) -> str:
    """Sign string data (Proof of Possession)."""
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def main():
    if len(sys.argv) < 2:
        print("Usage: python client_setup.py <username>")
        sys.exit(1)
        
    username = sys.argv[1]
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    
    priv_path = keys_dir / f"{username}_private.pem"
    pub_path = keys_dir / f"{username}_public.pem"
    
    # 1. Generate Link
    print(f"[1/3] Generating 2048-bit RSA Key Pair...")
    private_key, public_key = generate_key_pair()
    
    # 2. Save Locally
    save_key(private_key, priv_path, is_private=True)
    save_key(public_key, pub_path, is_private=False)
    print(f"      Saved: {priv_path}")
    print(f"      Saved: {pub_path}")
    
    # 3. Register with Server (PoP)
    print(f"[2/3] Generating Proof-of-Possession Signature...")
    signature = sign_data(private_key, username)
    
    # Prepare Public Key String
    pub_pem_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    payload = {
        "username": username,
        "public_key": pub_pem_str,
        "signature": signature
    }
    
    print(f"[3/3] Registering Identity with Server...")
    try:
        response = requests.post(f"{SERVER_URL}/register-key", json=payload)
        if response.status_code == 200:
            print("      ✅ Success! Public Key Registered.")
            print(f"      Server Response: {response.json()}")
        else:
            print(f"      ❌ Failed: {response.status_code}")
            print(f"      Error: {response.text}")
    except Exception as e:
        print(f"      ❌ Connection Error: {e}")

if __name__ == "__main__":
    main()
