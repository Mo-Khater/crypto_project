import socket
from key_exchange import DiffieHellman
from seed_encryption import SeedEncryptor
from seed_authentication import SeedAuthenticator
from stream_cipher import StreamCipher  # Assuming this module exists for OTP encryption
from utils import send_data, recv_data

class CommunicationClient:
    def __init__(self,seed, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.seed = seed
        self.dh_sender = DiffieHellman() # use Diffie-Hellman key exchange for secure key generation
        self.stream_cipher = StreamCipher(seed) # Initialize stream cipher with the seed
        self.shared_key_sender = None 
        self.encryptor_sender = None
        self.authenticator_sender =None

    def generated_client_shared_key(self,public_key):
        self.shared_key_sender = self.dh_sender.generate_shared_key(public_key)       
        self.encryptor_sender = SeedEncryptor(self.shared_key_sender)
        self.authenticator_sender = SeedAuthenticator(self.shared_key_sender)        
    
    def send_seed(self, seed: int,client_socket):
        iv, encrypted_seed = self.encryptor_sender.encrypt(seed)
        hmac_tag = self.authenticator_sender.generate_hmac(encrypted_seed)
        send_data(client_socket, iv)  
        send_data(client_socket, encrypted_seed)
        send_data(client_socket, hmac_tag)  
    
    def send_message(self, message: str,client_socket):
        encrypted_message = self.stream_cipher.encrypt(message)
        send_data(client_socket, encrypted_message)  

    def send_file_chunks(self, file_path, client_socket, chunk_size=10):
        with open(file_path, 'r') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break  
                self.send_message(chunk, client_socket)  # Send each chunk
                print(f"Sent chunk: {chunk}")
                
def start_client_communication():
    client = CommunicationClient(seed=1234567890987654321) 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a socket object
    client_socket.connect(('localhost', 12345))

    public_key_bytes =client.dh_sender.public_key.to_bytes((client.dh_sender.public_key.bit_length() + 7) // 8, 'big') # Convert public key to bytes
    send_data(client_socket, public_key_bytes)  # Send public key to server

    server_public_key = int.from_bytes(recv_data(client_socket), 'big')

    client.generated_client_shared_key(server_public_key)  # Generate shared key using server's public key
    client.send_seed(client.seed,client_socket)  # Send the seed to the server            

    client.send_file_chunks("input.txt", client_socket)  # Replace with your file path
    client_socket.close()
    
start_client_communication()
