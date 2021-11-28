import abc
import argparse
import time
from peewee import *
from itertools import count
from socket import ntohs, socket, PF_PACKET, SOCK_RAW
from playhouse.db_url import connect
import protocols

# This app can catalog assets through their ip address in a ethernet network

i = ' ' * 4  # Basic indentation level

db = connect('mysql://user:passw0rd@localhost:3306/ip')
packets = []


class BaseModel(Model):
    class Meta:
        database = db


# Database structure for peewee
class Communications(BaseModel):
    id = IntegerField(constraints=[SQL("UNSIGNED")])
    src_ip4 = CharField(16)
    dest_ip4 = CharField(16)
    src_ip6 = CharField()
    dest_ip6 = CharField()
    src_mac = CharField(17)
    dest_mac = CharField(17)
    src_port = SmallIntegerField(constraints=[SQL("UNSIGNED")])
    dest_port = SmallIntegerField(constraints=[SQL("UNSIGNED")])
    proto = CharField(10)
    flags = CharField(10)
    first_seen = DateTimeField()
    last_seen = DateTimeField()

    def __init__(self, src_ip4, dest_ip4, src_ip6, dest_ip6, src_mac, dest_mac, src_port, dest_port, proto,
                 flags, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.src_ip4 = src_ip4
        self.dest_ip4 = dest_ip4
        self.src_ip6 = src_ip6
        self.dest_ip6 = dest_ip6
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.src_port = src_port
        self.dest_port = dest_port
        self.proto = proto
        self.flags = flags


# Packet class for managing and recording packets
class Packet:
    def __init__(self, src_ip4, dest_ip4, src_ip6, dest_ip6, src_mac, dest_mac, src_port, dest_port, proto, flags):
        self.src_ip4 = src_ip4
        self.dest_ip4 = dest_ip4
        self.src_ip6 = src_ip6
        self.dest_ip6 = dest_ip6
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.src_port = src_port
        self.dest_port = dest_port
        self.proto = proto
        self.flags = flags

    def __eq__(self, other):
        if not isinstance(other, Packet):
            return NotImplemented
        return self.src_ip4 == other.src_ip4 and self.dest_ip4 == other.dest_ip4 and self.src_ip6 == other.src_ip6 and self.dest_ip6 == other.dest_ip6 and self.src_mac == other.src_mac and self.dest_mac == other.dest_mac and self.src_port == other.src_port and self.dest_port == other.dest_port and self.proto == other.proto and self.flags == other.flags


class PacketSniffer(object):
    def __init__(self, interface: str):
        self.interface = interface
        self.data = None
        self.protocol_queue = ['Ethernet']
        self.__observers = list()

    def register(self, observer):
        self.__observers.append(observer)

    def __notify_all(self, *args):
        for observer in self.__observers:
            observer.update(*args)
        del self.protocol_queue[1:]

    def execute(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            if self.interface is not None:
                sock.bind((self.interface, 0))
            for self.packet_num in count(1):
                raw_packet = sock.recv(9000)
                start: int = 0
                for proto in self.protocol_queue:
                    proto_class = getattr(protocols, proto)
                    end: int = start + proto_class.header_len
                    protocol = proto_class(raw_packet[start:end])
                    setattr(self, proto.lower(), protocol)
                    if protocol.encapsulated_proto is None:
                        break
                    self.protocol_queue.append(protocol.encapsulated_proto)
                    start = end
                self.data = raw_packet[end:]
                self.__notify_all(self)


class OutputMethod(abc.ABC):
    """Interface for the implementation of all classes responsible for further processing and/or output of the
    information gathered by the PacketSniffer class (referenced as 'subject')."""

    def __init__(self, subject):
        subject.register(self)

    @abc.abstractmethod
    def update(self, *args, **kwargs):
        pass


def insert_record(p):
    to_db = Communications(p.src_ip4, p.dest_ip4, p.src_ip6, p.dest_ip6, p.src_mac, p.dest_mac,
                           int(p.src_port) if p.src_port is not None else p.src_port,
                           int(p.dest_port) if p.dest_port is not None else p.dest_port, p.proto, p.flags)
    to_db.save()


def check_exist(packet):
    if len(packets) == 0:
        # print('first packet added')
        packets.append(packet)
        insert_record(packet)
        return True
    for ex_pk in packets:
        if ex_pk == packet:
            return True
    # print('new packet - adding')
    packets.append(packet)
    insert_record(packet)


class SniffToDB(OutputMethod):
    def __init__(self, subject, *, displaydata: bool):
        super().__init__(subject)
        self.p = None
        self.display_data = displaydata

    def update(self, packet):
        self.p = packet
        # print('Packet number {0}'.format(self.p.packet_num))
        pk = Packet(None, None, None, None, None, None, None, None, None, None)
        for proto in self.p.protocol_queue:
            if proto.lower() == 'ethernet':
                pk.src_mac = self.p.ethernet.source
                pk.dest_mac = self.p.ethernet.dest
                pk.proto = 'ethernet'
            if proto.lower() == 'ipv4':
                pk.src_ip4 = self.p.ipv4.source
                pk.dest_ip4 = self.p.ipv4.dest
                pk.proto = self.p.ipv4.encapsulated_proto
            if proto.lower() == 'ipv6':
                pk.src_ip6 = self.p.ipv6.source
                pk.dest_ip6 = self.p.ipv6.dest
            if proto.lower() == 'arp':
                if self.p.arp.oper == 1:  # ARP Request
                    pk.proto = 'arp-rq'
                    pk.src_ip4 = self.p.arp.target_proto
                    pk.dest_ip4 = self.p.arp.source_proto
                else:  # ARP Reply
                    pk.proto = 'arp-rl'
                    pk.src_ip4 = self.p.arp.target_proto
                    pk.dest_ip4 = self.p.arp.source_hdwr
            if proto.lower() == 'tcp':
                pk.proto = 'tcp'
                pk.src_port = self.p.tcp.sport
                pk.dest_port = self.p.tcp.dport
                pk.flags = self.p.tcp.flag_hex
            if proto.lower() == 'udp':
                pk.proto = 'udp'
                pk.src_port = self.p.udp.sport
                pk.dest_port = self.p.udp.dport
            if proto.lower() == 'icmp':
                pk.proto = 'icmp'
                pk.src_ip4 = self.p.ipv4.source
                pk.dest_ip4 = self.p.ipv4.dest
                pk.flags = self.p.icmp.type_txt
        check_exist(pk)
        # print(len(packets))

    def _display_packet_contents(self):
        if self.display_data is True:
            print('{0}[+] DATA:'.format(i))
            data = self.p.data.decode(errors='ignore').replace('\n', '\n{0}'.format(i * 2))
            print('{0}{1}'.format(i, data))


def sniff(interface: str, displaydata: bool):
    """Control the flow of execution of the Packet Sniffer tool."""

    packet_sniffer = PacketSniffer(interface)
    SniffToDB(subject=packet_sniffer, displaydata=displaydata)
    try:
        print('\n[>>>] Sniffer initialized. Waiting for incoming packets. Press Ctrl-C to abort...\n')
        packet_sniffer.execute()
    except KeyboardInterrupt:
        raise SystemExit('Aborting packet capture...')


if __name__ == '__main__':
    db.connect()
    packets_in_db = Communications.select().execute()
    packets = list(packets_in_db)
    parser = argparse.ArgumentParser(description='Python network packet sniffer.')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Interface from which packets will be captured (captures from all available interfaces '
                             'by default).')
    parser.add_argument('-d', '--displaydata', action='store_true', help='Output packet data during capture.')
    cli_args = parser.parse_args()
    sniff(interface=cli_args.interface, displaydata=cli_args.displaydata)
