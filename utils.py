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