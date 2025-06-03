from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import os

# Generate encryption key from password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt a message
def encrypt(message: str, password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return encrypted, salt

# Decrypt the message
def decrypt(encrypted_message: bytes, password: str, salt: bytes) -> str:
    key = generate_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Example usage
if __name__ == "__main__":
    message = input("Enter a message to encrypt: ")
    password = input("Enter a password: ")

    encrypted, salt = encrypt(message, password)
    print(f"\nEncrypted: {encrypted}")
    print(f"Salt: {salt.hex()}")

    # For decryption
    decrypt_password = input("\nEnter the password to decrypt: ")
    try:
        decrypted = decrypt(encrypted, decrypt_password, bytes.fromhex(salt.hex()))
        print(f"Decrypted: {decrypted}")
    except Exception as e:
        print("Decryption failed:", e)
