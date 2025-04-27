from scapy.all import *
import socket
import sys
import os
import time
from ipaddress import IPv4Address, AddressValueError
from contextlib import contextmanager


@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

def what_the_whois(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.send((ip + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    whois = ''
    for resp in response.decode().splitlines():
        if resp.startswith('%') or not resp.strip():
            continue
        elif resp.startswith('whois'):
            whois = resp.split(":")[1].strip()
            break
    return whois if whois else False

def make_info_raw(ip, whois):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois, 43))
    s.send((ip + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    whois_ip = dict()
    for ln in response.decode().splitlines():
        if ln.strip().startswith("%") or not ln.strip():
            continue
        else:
            if ln.strip().split(": ")[0].strip() == 'country':
                whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
            elif ln.strip().split(": ")[0].strip() == 'netname':
                whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
            elif ln.strip().split(": ")[0].strip() == 'origin':
                whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
    return whois_ip if whois_ip else False

def validate_request(ip):
    try:
        IPv4Address(ip)
        if whois := what_the_whois(ip):
            time.sleep(1)
            if info := make_info_raw(ip, whois):
                print(f"{info.get('netname')} {info.get('origin')} {info.get('country')}\n")
            else:
                print("No IP address data has been received.")
        else:
            #print("No information about the registrar.")
            print("local\n")
    except AddressValueError:
        print("IP-address not valid")
    except ConnectionResetError as ex:
        print(ex)

def tracert():
    ip = sys.argv[1]
    try:
        IPv4Address(ip)
    except AddressValueError:
        print("IP-address not valid")
        return
    raw_idx = 1
    for time_to_live in range(1, 31):
        with suppress_stdout():
            packet = sr1(IP(dst=ip,ttl=time_to_live)/UDP(dport=33434), timeout = 2)
            time.sleep(1)
        if packet is None:
            print(f'\n{raw_idx}. *\n')
        elif packet.type==3:
            print(f'\n{raw_idx}. {packet.src}({ip})')
            validate_request(packet.src)
            break
        else:
            print(f'\n{raw_idx}. {packet.src}')
            validate_request(packet.src)
        raw_idx += 1
tracert()
