"""
Fortress Developer CLI - Artifact Upload Tool
Simulates the "Supply Chain Source" for secure artifact uploads.
"""
import sys
import base64
import hashlib
from pathlib import Path

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

if __name__ == "__main__":
    main()
