import socket
from key_exchange import DiffieHellman
from seed_encryption import SeedEncryptor
from seed_authentication import SeedAuthenticator
from stream_cipher import StreamCipher  # Assuming this module exists for OTP encryption

def send_data(sock, data: bytes):
    """
    Sends data with a 4-byte big-endian length prefix.
    """
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big'))  # Send 4-byte length
    sock.sendall(data)  # Send actual data


def recv_data(sock) -> bytes:
    """
    Receives data preceded by a 4-byte big-endian length prefix.
    Returns the full payload as bytes.
    """
    def recv_all(n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                raise ConnectionError("Socket connection closed")
            data += packet
        return data

    length_bytes = recv_all(4)
    length = int.from_bytes(length_bytes, 'big')
    return recv_all(length)

class CommunicationClient:
    def __init__(self,seed, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.seed = seed
        # Create Diffie-Hellman key exchange instance and generate shared key
        self.dh_sender = DiffieHellman()
        self.stream_cipher = StreamCipher(seed)
        self.shared_key_sender = None
        self.encryptor_sender = None
        self.authenticator_sender =None

    def generated_client_shared_key(self,public_key):
        self.shared_key_sender = self.dh_sender.generate_shared_key(public_key)       
        self.encryptor_sender = SeedEncryptor(self.shared_key_sender)
        self.authenticator_sender = SeedAuthenticator(self.shared_key_sender)        
    
    def send_seed(self, seed: int,client_socket):
        # Encrypt the seed and generate HMAC
        iv, encrypted_seed = self.encryptor_sender.encrypt(seed)
        hmac_tag = self.authenticator_sender.generate_hmac(encrypted_seed)
        send_data(client_socket, iv)  # Send IV with length prefix
        send_data(client_socket, encrypted_seed)
        send_data(client_socket, hmac_tag)  # Send HMAC tag with length prefix
    
    def send_message(self, message: str,client_socket):
        encrypted_message = self.stream_cipher.encrypt(message)
        send_data(client_socket, encrypted_message)  # Send encrypted message with length prefix

    def send_file_chunks(self, file_path, client_socket, chunk_size=10):
        with open(file_path, 'r') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break  # End of file
                self.send_message(chunk, client_socket)  # Send each chunk
                print(f"Sent chunk: {chunk}")

client = CommunicationClient(seed=1234567890987654321) 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

public_key_bytes =client.dh_sender.public_key.to_bytes((client.dh_sender.public_key.bit_length() + 7) // 8, 'big')
send_data(client_socket, public_key_bytes)  # Send public key to server

server_public_key = int.from_bytes(recv_data(client_socket), 'big')

client.generated_client_shared_key(server_public_key)  # Generate shared key using server's public key
client.send_seed(client.seed,client_socket)  # Send the seed to the server

# while True:
#     # Read message from terminal
#     message_to_send = input("Enter message to send (type 'exit' to quit): ")
#     if message_to_send.lower() == 'exit':
#         print("Exiting...")
#         break
#     client.send_message(message_to_send,client_socket=client_socket)  # Send the message to the server


            

client.send_file_chunks("input.txt", client_socket)  # Replace with your file path
client_socket.close()
