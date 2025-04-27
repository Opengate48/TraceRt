import time
import socket
import struct
client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#print(int(time.time()))
t1 = time.time()
msg_to_server = b"\x23" + 39*b"\x00" + int(t1).to_bytes(4,byteorder='big') + 4*b"\x00"
client_sock.sendto(msg_to_server, ("127.0.0.1", 123))
msg_from_server, _ = client_sock.recvfrom(2048)
t4 = time.time()
parsed_msg = struct.unpack("!12I", msg_from_server)
t2 = parsed_msg[8]
t3 = parsed_msg[10]
tm = int(t3 + ((t4 - t1) + (t3 - t2))/2)
print(time.ctime(tm))
print(tm)
print(int(time.time()))