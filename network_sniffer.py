import argparse
import socket
import struct
from ctypes import Structure, c_ubyte, c_ushort, c_uint32

# Define the IP header structure
class IPHeader(Structure):
    _fields_ = [
        ("ihl_ver",   c_ubyte),
        ("tos",       c_ubyte),
        ("total_len", c_ushort),
        ("id",        c_ushort),
        ("offset",    c_ushort),
        ("ttl",       c_ubyte),
        ("protocol",  c_ubyte),
        ("checksum",  c_ushort),
        ("src",       c_uint32),
        ("dst",       c_uint32)
    ]

    def __new__(cls, raw_data):
        return cls.from_buffer_copy(raw_data)

    def __init__(self, raw_data):
        self.src_ip = socket.inet_ntoa(struct.pack("!I", self.src))
        self.dst_ip = socket.inet_ntoa(struct.pack("!I", self.dst))
        self.protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol_name = self.protocol_names.get(self.protocol, str(self.protocol))

# Sniff function to capture and process packets
def sniff_packets(proto):
    protocol_map = {"TCP": socket.IPPROTO_TCP, "UDP": socket.IPPROTO_UDP, "ICMP": socket.IPPROTO_ICMP}
    if proto.upper() not in protocol_map:
        print("Invalid protocol specified. Use TCP, UDP, or ICMP.")
        return
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol_map[proto.upper()])
    
    while True:
        raw_data, addr = sock.recvfrom(65535)
        ip_header = IPHeader(raw_data[:20])
        print(f"Protocol: {ip_header.protocol_name} Source: {ip_header.src_ip} Destination: {ip_header.dst_ip}")


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-p", "--protocol", type=str, help="Specify the protocol (TCP, UDP, ICMP)")
    args = parser.parse_args()
    protocol = args.protocol
    
    if not protocol:
        print("Please specify a protocol using the -p or --protocol option.")
        return
    
    print(f"Sniffer started sniffing {protocol.upper()} packets:")
    sniff_packets(protocol)


if __name__ == "__main__":
    main()
