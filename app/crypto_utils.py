import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

    @staticmethod
    def generate_rsa_key_pair():
        """
        Generates an RSA private/public key pair (2048-bit).
        
        Returns:
            private_key: The RSA private key object.
            public_key: The RSA public key object.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key, private_key.public_key()

    @staticmethod
    def save_key_to_file(key, file_path: str, is_private: bool = False) -> None:
        """
        Saves an RSA key to a PEM file.
        
        Args:
            key: The key object (private/public).
            file_path: Absolute path to save the key.
            is_private: Boolean indicating if it's a private key.
        """
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
        
        with open(file_path, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_private_key(file_path: str):
        """Loads Private Key from a PEM file."""
        with open(file_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

    @staticmethod
    def load_public_key(file_path: str):
        """Loads Public Key from a PEM file."""
        with open(file_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def sign_data(private_key, data: bytes) -> bytes:
        """
        Signs data using the RSA Private Key (RSA-PSS with SHA-256).
        
        Args:
            private_key: The RSA private key.
            data: The data to sign.
            
        Returns:
            The digital signature (bytes).
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
        """
        Verifies a digital signature (RSA-PSS with SHA-256).
        
        Args:
            public_key: The RSA public key.
            data: The original data that was signed.
            signature: The signature to verify.
            
        Returns:
            True if valid, False otherwise.
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
