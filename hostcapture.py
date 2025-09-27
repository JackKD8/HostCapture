import socket
from scapy.all import sniff, IP, TCP, UDP, Raw
import re


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

def packet_handler(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst


        if src_ip == LOCAL_IP or dst_ip == LOCAL_IP:
            direction = "out" if src_ip == LOCAL_IP else "in"
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"


            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                try:
                    data = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if data.startswith('GET') or data.startswith('POST'):
                        print(f"[HTTP] {src_ip} -> {dst_ip} [{data.split()[0]} {data.split()[1]}]")
                        return
                except Exception:
                    pass

            if protocol == "TCP":
                print(f"[TCP] {src_ip} -> {dst_ip}")
            elif protocol == "UDP":
                print(f"[UDP] {src_ip} -> {dst_ip}")

if __name__ == "__main__":
    print(f"[*] Starting network capture on {LOCAL_IP}")

    sniff(prn=packet_handler, store=0)
