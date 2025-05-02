import random

# 2048-bit MODP Group from RFC 3526 (Group 14)
MODP_2048_P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D
6D51C245E485B576625E7EC6F44C42E9A63A3620
FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", ""), 16) 

MODP_2048_G = 2

class DiffieHellman:
    def __init__(self, p=None, g=None):
        self.p = p or MODP_2048_P
        self.g = g or MODP_2048_G
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, other_public_key):
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret

if __name__ == "__main__":
    # Sender side
    sender = DiffieHellman()
    print("Sender public key:", sender.public_key)

    # Receiver side
    receiver = DiffieHellman(p=sender.p, g=sender.g)
    print("Receiver public key:", receiver.public_key)

    # Exchange and generate shared keys
    sender_shared = sender.generate_shared_key(receiver.public_key)
    receiver_shared = receiver.generate_shared_key(sender.public_key)

    print("Sender shared key: ", sender_shared)
    print("Receiver shared key:", receiver_shared)

    assert sender_shared == receiver_shared, "Shared keys don't match!"
