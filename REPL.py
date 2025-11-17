import socket
import ssl
import struct

HOST = "your.server.address"
PORT = 12345

# ❗ Disable certificate verification (for testing only)
context = ssl._create_unverified_context()

# Connect TCP → SSL
raw_sock = socket.create_connection((HOST, PORT))
ssock = context.wrap_socket(raw_sock, server_hostname=HOST)

print("Connected to server:", HOST, PORT)
print("Enter integers to send (space-separated), or 'quit' to exit:")

while True:
    user_input = input("Ints> ").strip()
    if user_input.lower() in ("quit", "exit"):
        break

    try:
        # Convert input into a list of ints
        values = [int(x) for x in user_input.split()]
    except ValueError:
        print("Invalid input. Enter space-separated integers.")
        continue

    # Prompt for a string
    msg = input("String> ")
    msg_bytes = msg.encode("utf-8")

    # Build struct format: N ints + string length
    fmt = "!" + "i" * len(values) + "I"
    packet = struct.pack(fmt, *values, len(msg_bytes)) + msg_bytes

    # Send packet
    ssock.sendall(packet)
    print("Sent packet:", packet.hex())

print("Closing connection.")
ssock.close()
