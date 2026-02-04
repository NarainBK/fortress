"""
Fortress Developer CLI - Artifact Upload Tool
Simulates the "Supply Chain Source" for secure artifact uploads.
"""
import sys
import base64
import hashlib
import requests
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Server configuration
SERVER_URL = "http://localhost:8000"

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def read_file_as_base64(file_path: str) -> str:
    """Read file and return Base64 encoded content."""
    with open(file_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")

def load_private_key(key_path: str):
    """Load RSA private key from PEM file."""
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_hash(private_key, hash_bytes: bytes) -> str:
    """Sign hash using RSA-PSS and return Base64 encoded signature."""
    signature = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")

def main():
    """Main CLI entry point."""
    if len(sys.argv) < 3:
        print("Usage: python client_upload.py <file_path> <private_key_path>")
        print("Example: python client_upload.py ./app-v1.exe ./keys/dev_private.pem")
        sys.exit(1)
    
    file_path = sys.argv[1]
    private_key_path = sys.argv[2]
    
    # Validate paths
    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    if not Path(private_key_path).exists():
        print(f"Error: Private key not found: {private_key_path}")
        sys.exit(1)
    
    # Step 1: Calculate file hash
    print(f"[1/4] Calculating SHA-256 hash...")
    file_hash = calculate_file_hash(file_path)
    print(f"      Hash: {file_hash}")
    
    # Step 2: Read and encode file
    print(f"[2/4] Encoding file to Base64...")
    file_b64 = read_file_as_base64(file_path)
    print(f"      Size: {len(file_b64)} bytes (encoded)")
    
    # Step 3: Sign the hash
    print(f"[3/4] Signing hash with private key...")
    private_key = load_private_key(private_key_path)
    signature_b64 = sign_hash(private_key, file_hash.encode())
    print(f"      Signature generated successfully")
    
    # Step 4: Upload to server
    print(f"[4/4] Uploading to server...")
    payload = {
        "filename": Path(file_path).name,
        "username": "developer", # Hardcoded for this demo
        "file_b64": file_b64,
        "signature": signature_b64,
        "hash": file_hash
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/upload", json=payload)
        if response.status_code == 200:
            print(f"      Upload successful!")
            print(f"      Response: {response.json()}")
        else:
            print(f"      Upload failed: {response.status_code}")
            print(f"      Response: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"      Error: Could not connect to server at {SERVER_URL}")

if __name__ == "__main__":
    main()
