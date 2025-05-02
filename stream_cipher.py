from lcg import LCG

class StreamCipher:
    def __init__(self, seed):
        self.lcg = LCG(seed)

    def xor_bytes(self, data: bytes) -> bytes:
        keystream = self.lcg.get_keystream(len(data))
        return bytes([b ^ k for b, k in zip(data, keystream)])

    def encrypt(self, plaintext: str) -> bytes:
        return self.xor_bytes(plaintext.encode('utf-8')) # convert string to bytes

    def decrypt(self, ciphertext: bytes) -> str:
        decrypted_bytes = self.xor_bytes(ciphertext)
        return decrypted_bytes.decode('utf-8')

if __name__ == "__main__":
    seed = 987654321
    message = "HELLOCRYPTO"
    
    cipher = StreamCipher(seed)
    encrypted = cipher.encrypt(message)
    print("Encrypted bytes:", encrypted)

    # Use the same seed for decryption
    cipher2 = StreamCipher(seed)
    decrypted = cipher2.decrypt(encrypted)
    print("Decrypted message:", decrypted)
