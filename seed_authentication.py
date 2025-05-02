import hmac
import hashlib

class SeedAuthenticator:
    def __init__(self, shared_secret):
        # Derive a 256-bit key for HMAC
        self.key = hashlib.sha256(str(shared_secret).encode()).digest()

    def generate_hmac(self, message: bytes) -> bytes:
        return hmac.new(self.key, message, hashlib.sha256).digest()

    def verify_hmac(self, message: bytes, received_hmac: bytes) -> bool:
        expected_hmac = self.generate_hmac(message)
        return hmac.compare_digest(expected_hmac, received_hmac)

if __name__ == "__main__":
    shared_secret = 1234567890987654321  # Simulated DH shared secret

    authenticator = SeedAuthenticator(shared_secret)
    
    message = b"Encrypted seed here"
    tag = authenticator.generate_hmac(message)
    print("HMAC tag:", tag.hex())

    # Receiver side verification
    is_valid = authenticator.verify_hmac(message, tag)
    print("HMAC valid:", is_valid)

    # Try tampering
    fake = b"Tampered message"
    is_valid_fake = authenticator.verify_hmac(fake, tag)
    print("HMAC valid after tamper:", is_valid_fake)
