import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoUtils:
    """
    Cryptographic utility class.
    Implements NIST-compliant hashing (SHA-256) and encryption (AES-256-GCM).
    """

    @staticmethod
    def generate_file_hash(file_path: str) -> str:
        """
        Calculates SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Hexadecimal string of the hash.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """
        Encrypts data using AES-256-GCM.
        
        Args:
            data: The plaintext bytes to encrypt.
            key: The 256-bit (32 byte) encryption key.
            
        Returns:
            Tuple: (nonce, ciphertext).
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # NIST recommended is 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce, ciphertext

    @staticmethod
    def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
        """
        Decrypts data using AES-256-GCM.
        
        Args:
            nonce: The 12-byte nonce used during encryption.
            ciphertext: The encrypted data.
            key: The 256-bit decryption key.
            
        Returns:
            The decrypted plaintext bytes.
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def generate_aes_key() -> bytes:
        """Generates a random 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)
