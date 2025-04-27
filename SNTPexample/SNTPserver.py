import socket
import time
import struct
import sys

maximum_shift_value = 2 ** 32 / 2 - time.time()
minimum_shift_value = -(2 ** 32 / 2 + time.time()) 
offset = int(sys.argv[1])
if (offset > maximum_shift_value or offset < minimum_shift_value):
    print("Invalid offset")
    sys.exit()
def get_timestamp():
    strat1_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t1 = time.time()
    sntp_head = b"\x23" + 39*b"\x00" + int(t1).to_bytes(4,byteorder='big') + 4*b"\x00"
    strat1_sock.sendto(sntp_head, ('0.uk.pool.ntp.org', 123))
    sntp_head_from_str1, addr = strat1_sock.recvfrom(2048)
    t4 = time.time()
    parsed_head = struct.unpack('!12I', sntp_head_from_str1)
    t2 = parsed_head[8] - 2208988800
    t3 = parsed_head[10] - 2208988800
    return int(t3 + ((t4 - t1) + (t3 - t2))/2)


server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_sock.bind(("127.0.0.1", 123))
#offset = 100
while True:
    msg_from_client, addr = server_sock.recvfrom(1024)
    my_t2 = get_timestamp()
    #print(msg_from_client)
    if msg_from_client:
        parsed_msg = struct.unpack('!12I', msg_from_client)
        vn = struct.unpack('!B', msg_from_client[0:1])[0] // 2**3
        my_t1 = parsed_msg[10]
        my_t3 = get_timestamp() + offset/1.5
        msg_to_client = int(vn + 4).to_bytes(1,byteorder='big') + int(3).to_bytes(1,byteorder='big') + 22*b"\x00" + int(my_t1).to_bytes(4,byteorder='big') + 4*b"\x00" + int(my_t2).to_bytes(4,byteorder='big') + 4*b"\x00" + int(my_t3).to_bytes(4,byteorder='big') + 4*b"\x00" 
        server_sock.sendto(msg_to_client, addr)
    else:
        print("nope")

