import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class SeedEncryptor:
    def __init__(self, shared_secret):
        # Derive a 256-bit AES key from shared secret using SHA-256
        self.key = hashlib.sha256(str(shared_secret).encode()).digest()

    def encrypt(self, seed: int) -> tuple[bytes, bytes]:
        seed_bytes = str(seed).encode('utf-8')
        
        # Pad seed to AES block size (16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_seed = padder.update(seed_bytes) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_seed) + encryptor.finalize()
        return iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes) -> int:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_seed = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        seed_bytes = unpadder.update(padded_seed) + unpadder.finalize()
        return int(seed_bytes.decode('utf-8'))


if __name__ == "__main__":
    shared_secret = 1234567890987654321  # Pretend this came from DH

    seed_encryptor = SeedEncryptor(shared_secret)
    seed = 999888777666

    iv, encrypted = seed_encryptor.encrypt(seed)
    print("Encrypted seed:", encrypted)

    decrypted = seed_encryptor.decrypt(iv, encrypted)
    print("Decrypted seed:", decrypted)

    assert decrypted == seed, "Seed mismatch!"
