#! /usr/bin/python3

import string
import argparse
import socket
import os
from scapy.all import *
from ipaddress import IPv4Address


BUFF_SIZE = 1 << 16


TARGET_ADDRESS = "179.179.179.179"
TARGET_NAME = "holy.diver"


def load_lyrics(filename):
    file = open(filename, "r")

    trans_table = str.maketrans('', '', string.punctuation)

    lyrics = [line.strip().lower() for line in file]
    lyrics = [line.translate(trans_table) for line in lyrics]
    lyrics = [".".join(line.split()) for line in lyrics if line]

    file.close()

    return lyrics


def create_raw_socket(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(socket.ETH_P_ALL))
    sock.bind((iface, 0))
    return sock


def get_rdns_address(name):
    if "in-addr.arpa" not in name:
        return None

    addr = name.split(".")
    addr = addr[:4]
    addr = addr[::-1]
    return ".".join(addr)


class HolyDiver:
    def __init__(self, args):
        self.args = args

    def init(self):
        self.lyrics = load_lyrics(self.args.lyrics)
        self.local_socket = create_raw_socket(self.args.local_iface)
        self.cloud_socket = create_raw_socket(self.args.cloud_iface)

        self.hi_address = IPv4Address(TARGET_ADDRESS)
        self.lo_address = IPv4Address(int(self.hi_address) - len(self.lyrics))

        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def generate_dns_response(self, packet, queries, ar):
        ether = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
        )

        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
        )

        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport
        )

        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=len(queries),
            ancount=len(ar),
            nscount=0,
            arcount=0,
            ar=ar)

        response_packet = ether/ip/udp/dns
        return response_packet

    def respond_host_address(self, packet, queries):
        # https://jasonmurray.org/posts/2020/scapydns/
        print("sending host address")

        ar = [DNSRR(rrname=name, type='A', ttl=600, rdata=TARGET_ADDRESS)
              for name in queries]

        response_packet = self.generate_dns_response(packet, queries, ar)
        self.local_socket.send(response_packet.__bytes__())
        print("host address sent")

    def respond_rdns(self, packet, queries):
        print("sending rdns")

        ar = []
        for name in queries:
            addr = get_rdns_address(name.decode("utf-8").lower().rstrip("."))
            idx = int(IPv4Address(addr)) - int(self.lo_address)
            rdata = self.lyrics[idx] if idx < len(self.lyrics) else TARGET_NAME

            ar.append(DNSRR(rrname=name, type='PTR',
                      ttl=600, rdata=rdata))

        response_packet = self.generate_dns_response(packet, queries, ar)
        self.local_socket.send(response_packet.__bytes__())
        print("rdns sent")

    def is_holy_diver_reverse_query(self, qname_str):
        addr = get_rdns_address(qname_str)

        if addr is None:
            return False

        addr = int(IPv4Address(addr))

        return int(self.lo_address) <= addr and addr <= int(self.hi_address)

    def process_dns_ltc(self, data, packet):
        dns = packet[DNS]

        if dns.qr != 0:  # its response
            print("forward dns because it's not query")
            self.cloud_socket.send(data)

        holy_diver_queries = []
        holy_diver_reverse_queries = []
        other_queries = []

        for query in dns.qd:
            qname_str = query.qname.decode("utf-8").lower().rstrip(".")

            if qname_str == TARGET_NAME:
                holy_diver_queries.append(query.qname)
            elif self.is_holy_diver_reverse_query(qname_str):
                holy_diver_reverse_queries.append(query.qname)
            else:
                other_queries.append(query)

        if holy_diver_queries:
            self.respond_host_address(packet, holy_diver_queries)

        if holy_diver_reverse_queries:
            self.respond_rdns(packet, holy_diver_reverse_queries)

        if other_queries:
            print("forward dns with other hosts")
            packet[DNS].qd = other_queries
            packet[DNS].qdcount = len(other_queries)
            self.cloud_socket.send(packet.__bytes__())

    def calculate_line_address(self, ttl):
        ip = int(self.lo_address) + ttl - 1
        return str(IPv4Address(ip))

    def send_line(self, data, packet):
        print("sending fake TTL ICMP")

        ether = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
        )

        ip = IP(
            src=self.calculate_line_address(packet[IP].ttl),
            dst=packet[IP].src
        )

        icmp = ICMP(
            type=11,
            code=0,
        )

        response = (
            ether /
            ip /
            icmp /
            packet[IP].__bytes__()[:(packet[IP].ihl * 4)] /
            packet[IP].payload.__bytes__()[:8]
        )

        self.local_socket.send(response.__bytes__())

        print("fake TTL ICMP sent")

    def destination_reached_icmp_echo(self, data, packet):
        print("sending echo response (target reached)")
        ether = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
        )

        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
        )

        icmp = ICMP(
            type=0,
            code=0,
            id = packet[ICMP].id,
            seq = packet[ICMP].seq
        )

        data = packet[ICMP].payload
        response = ether/ip/icmp/data
        self.local_socket.send(response.__bytes__())
        print("echo response sent")
         

    def destination_reached_other(self, data, packet):
        print("sending destination is unreachable (target reached)")
        ether = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
        )

        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
        )

        icmp = ICMP( # port unreachable
            type=3,
            code=3,
        )

        response = (
            ether /
            ip /
            icmp /
            packet[IP].__bytes__()[:(packet[IP].ihl * 4)] /
            packet[IP].payload.__bytes__()[:8]
        )

        self.local_socket.send(response.__bytes__())
        print("destination is unreachable sent")

    def destination_reached(self, data, packet):
        if ICMP in packet and packet[ICMP].type == 8:
            self.destination_reached_icmp_echo(data, packet)
        else:
            self.destination_reached_other(data, packet)

    def process_ip_ltc(self, data, packet):
        if packet[IP].ttl <= len(self.lyrics):
            self.send_line(data, packet)
        else:
            self.destination_reached(data, packet)

    def process_ltc_packet(self, data):
        packet = Ether(data)

        if IP in packet and packet[IP].dst == TARGET_ADDRESS:
            self.process_ip_ltc(data, packet)
        elif UDP in packet and DNS in packet:
            self.process_dns_ltc(data, packet)
        else:
            print("forward packet because it's neither dns nor our target")
            self.cloud_socket.send(data)

    def local_to_cloud(self):
        while True:
            data = self.local_socket.recv(BUFF_SIZE)
            self.process_ltc_packet(data)

    def cloud_to_local(self):
        """ just resend all packets """

        while True:
            data = self.cloud_socket.recv(BUFF_SIZE)
            self.local_socket.send(data)

    def start(self):
        res = os.fork()
        if (res == 0):
            self.local_to_cloud()
        else:
            self.cloud_to_local()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--local-iface", required=True,
                        help="interface connected to local network")
    parser.add_argument("-c", "--cloud-iface", required=True,
                        help="interface connected to cloud")
    parser.add_argument(
        "--lyrics", help="file containg song lyrics", default="holy.diver.txt")

    return parser.parse_args()


def main():
    args = parse_args()
    holy_diver = HolyDiver(args)
    holy_diver.init()
    holy_diver.start()


if __name__ == "__main__":
    main()
