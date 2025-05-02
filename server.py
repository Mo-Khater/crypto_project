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


class CommunicationServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.seed = None
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Allow up to 5 clients to connect
        print(f"Server listening on {self.host}:{self.port}")

        # Create Diffie-Hellman key exchange instance and generate shared key
        self.dh_receiver = DiffieHellman()
        self.shared_key_receiver = None
        self.encryptor_receiver =None
        self.authenticator_receiver = None
        self.StreamCipher = None

    def generated_server_shared_key(self,public_key):
        self.shared_key_receiver = self.dh_receiver.generate_shared_key(public_key)       
        self.encryptor_receiver = SeedEncryptor(self.shared_key_receiver)
        self.authenticator_receiver = SeedAuthenticator(self.shared_key_receiver)   
        
    def recieve_seed(self, client_socket):
        # Receive the seed from the client
        iv = recv_data(client_socket)  # Receive IV with length prefix
        encrypted_seed = recv_data(client_socket)  # Receive encrypted seed with length prefix
        hmac_tag = recv_data(client_socket)  # Receive HMAC tag with length prefix
        self.seed = self.encryptor_receiver.decrypt(iv, encrypted_seed)
        self.StreamCipher = StreamCipher(self.seed)  # Initialize stream cipher with the seed
        print(f"Received seed: {self.seed}")
        if not self.authenticator_receiver.verify_hmac(encrypted_seed, hmac_tag):
            raise ValueError("HMAC verification failed! Data integrity compromised.")
    
    def receive_data(self, client_socket):
        # Receive the encrypted message from the client
        encrypted_message = recv_data(client_socket)  # Receive encrypted message with length prefix
        if not encrypted_message:
            print("No data received. Closing connection.")
            return
        decrypted_message = self.StreamCipher.decrypt(encrypted_message)
        print(f"Decrypted message: {decrypted_message}")
        return decrypted_message
    
    def receive_file_chunks(self, client_socket, output_file="output.txt"):
        with open(output_file, 'w') as file:
            while True:
                try:
                    decrypted_chunk = self.receive_data(client_socket)
                    file.write(decrypted_chunk)
                    print(f"Received: {decrypted_chunk}")
                except (ConnectionError, ValueError):
                    break  # Client disconnected or error
        
    def start_server(self):
        
        client_socket, client_address = self.server_socket.accept()
        # client_public_key = int.from_bytes(client_socket.recv(16), 'big')  # Receive client's public key
        # key_len = int.from_bytes(client_socket.recv(2), 'big')
        # client_public_key = int.from_bytes(client_socket.recv(key_len), 'big')
        client_public_key = int.from_bytes(recv_data(client_socket), 'big')

        self.generated_server_shared_key(client_public_key)  # Generate shared key using client's public key
        
        # public_key_bytes = self.dh_receiver.public_key.to_bytes((self.dh_receiver.public_key.bit_length() + 7) // 8, 'big')
        # client_socket.send(len(public_key_bytes).to_bytes(2, 'big'))
        # client_socket.send(public_key_bytes)
        public_key_bytes = self.dh_receiver.public_key.to_bytes((self.dh_receiver.public_key.bit_length() + 7) // 8, 'big')
        send_data(client_socket, public_key_bytes)  # Send server's public key with length prefix
        
        self.recieve_seed(client_socket)
        self.receive_file_chunks(client_socket)
        client_socket.close()
        # while True:
        #     try:
        #         self.receive_data(client_socket)
        #     except Exception as e:
        #         print(f"Error: {e}")
        #         client_socket.close()
        #     # Close the client connection after processing

if __name__ == "__main__":
    server = CommunicationServer()
    server.start_server()
