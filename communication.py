# import os
# from key_exchange import DiffieHellman
# from seed_encryption import SeedEncryptor
# from seed_authentication import SeedAuthenticator
# from stream_cipher import StreamCipher

# class CommunicationModule:
#     def __init__(self):
#         self.dh_sender = DiffieHellman()
#         self.dh_receiver = DiffieHellman(p=self.dh_sender.p, g=self.dh_sender.g)

#         # Generate shared keys
#         self.shared_key_sender = self.dh_sender.generate_shared_key(self.dh_receiver.public_key)
#         self.shared_key_receiver = self.dh_receiver.generate_shared_key(self.dh_sender.public_key)

#         # Ensure both parties have the same shared key
#         assert self.shared_key_sender == self.shared_key_receiver, "Shared keys don't match!"

#         # Create encryptor and authenticator for both sender and receiver
#         self.encryptor_sender = SeedEncryptor(self.shared_key_sender)
#         self.authenticator_sender = SeedAuthenticator(self.shared_key_sender)

#         self.encryptor_receiver = SeedEncryptor(self.shared_key_receiver)
#         self.authenticator_receiver = SeedAuthenticator(self.shared_key_receiver)

#     def sender_process(self, seed: int):
#         # Encrypt the seed and generate HMAC
#         iv, encrypted_seed = self.encryptor_sender.encrypt(seed)
#         hmac_tag = self.authenticator_sender.generate_hmac(encrypted_seed)

#         # Simulate sending: Save to files (sender side)
#         with open("sender_iv.bin", "wb") as file:
#             file.write(iv)

#         with open("sender_encrypted_seed.bin", "wb") as file:
#             file.write(encrypted_seed)

#         with open("sender_hmac.bin", "wb") as file:
#             file.write(hmac_tag)

#     def receiver_process(self):
#         # Simulate receiving: Read from files (receiver side)
#         with open("sender_iv.bin", "rb") as file:
#             iv = file.read()

#         with open("sender_encrypted_seed.bin", "rb") as file:
#             encrypted_seed = file.read()

#         with open("sender_hmac.bin", "rb") as file:
#             hmac_tag = file.read()

#         # Verify the HMAC
#         if not self.authenticator_receiver.verify_hmac(encrypted_seed, hmac_tag):
#             raise ValueError("HMAC verification failed! Data integrity compromised.")

#         # Decrypt the seed
#         decrypted_seed = self.encryptor_receiver.decrypt(iv, encrypted_seed)
#         print(f"Decrypted seed: {decrypted_seed}")

# if __name__ == "__main__":
#     # Seed to be sent (encrypted)
#     seed_to_send = 987654321

#     comm = CommunicationModule()

#     # Sender side process
#     comm.sender_process(seed_to_send)

#     # Receiver side process (simulates receiving and decrypting)
#     comm.receiver_process()
