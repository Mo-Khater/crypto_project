import random

class DiffieHellman:
    def __init__(self, p=None, g=None):
        # Common small primes for demonstration; in production, use large safe primes.
        self.p = p or 0xFFFFFFFB  # 32-bit prime
        self.g = g or 5
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
