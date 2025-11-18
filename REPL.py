import socket
import ssl
import struct

HOST = "127.0.0.1"
PORT = 9000

# Disable certificate verification (testing only)
context = ssl._create_unverified_context()

# Connect TCP → SSL
raw_sock = socket.create_connection((HOST, PORT))
sock = context.wrap_socket(raw_sock, server_hostname=HOST)

# ------------------------------
# Protocol helpers
# ------------------------------

def recv_exact(sock, n):
    """Read exactly n bytes or raise."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Server closed connection")
        buf += chunk
    return buf

def send_message(msg_id, payload: bytes):
    """| 1 byte msg_id | 4-byte length | payload |"""
    header = struct.pack(">BI", msg_id, len(payload))
    sock.sendall(header + payload)

def recv_message():
    """Read a full message according to the protocol."""
    # 1 byte msg ID
    msg_id_bytes = recv_exact(sock, 1)
    msg_id = msg_id_bytes[0]

    # 4 byte length
    len_bytes = recv_exact(sock, 4)
    length = struct.unpack(">I", len_bytes)[0]

    payload = recv_exact(sock, length)

    return msg_id, payload


# ------------------------------
# REPL Loop
# ------------------------------

print("Connected to {}:{} (TLS)".format(HOST, PORT))
print("Protocol = |1 byte msg_id|4 byte len|payload|\n")
print("Enter commands like: 1 hello world")

while True:
    try:
        line = input("> ").strip()
        if not line:
            continue
        
        parts = line.split(" ", 1)
        if len(parts) == 1:
            msg_id = int(parts[0])
            payload = b""
        else:
            msg_id = int(parts[0])
            payload = parts[1].encode()

        send_message(msg_id, payload)

        print("Waiting for server...")
        resp_id, resp_payload = recv_message()

        print(f"[Server Response]")
        print(f"  msg_id = {resp_id}")
        print(f"  length = {len(resp_payload)}")
        print(f"  payload = {resp_payload!r}")
        print()

    except KeyboardInterrupt:
        print("\nExiting.")
        break

    except Exception as e:
        print("ERROR:", e)
        break

sock.close()
