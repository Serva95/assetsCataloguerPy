import pyshark
from peewee import *
from playhouse.db_url import connect
import datetime
#import multiprocessing
#import time

db_username = "external"
db_password = "passw0rd"
db_url = "localhost:3306"
database_name = "ip"

db = connect(f"mysql://{db_username}:{db_password}@{db_url}/{database_name}")

packets = []
interface = "eth0" # Interfaccia sulla quale mettersi in ascolto dei pacchetti
bpf_filter = None
output_file = None


class BaseModel(Model):
    class Meta:
        database = db


class Communications(BaseModel):
    id = IntegerField(constraints=[SQL("UNSIGNED")])
    src_ip4 = CharField(16)
    dest_ip4 = CharField(16)
    src_ip6 = CharField(32)
    dest_ip6 = CharField(32)
    src_mac = CharField(17)
    dest_mac = CharField(17)
    src_port = SmallIntegerField(constraints=[SQL("UNSIGNED")])
    dest_port = SmallIntegerField(constraints=[SQL("UNSIGNED")])
    proto = CharField(32)
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


class Packet:
    def __init__(self, src_ip4, dest_ip4, src_ip6, dest_ip6, src_mac, dest_mac, src_port, dest_port, proto, flags):
        self.src_ip4   = str(src_ip4)   if src_ip4   is not None else None
        self.dest_ip4  = str(dest_ip4)  if dest_ip4  is not None else None
        self.src_ip6   = str(src_ip6)   if src_ip6   is not None else None
        self.dest_ip6  = str(dest_ip6)  if dest_ip6  is not None else None
        self.src_mac   = str(src_mac)   if src_mac   is not None else None
        self.dest_mac  = str(dest_mac)  if dest_mac  is not None else None
        self.src_port  = int(src_port)  if src_port  is not None else None
        self.dest_port = int(dest_port) if dest_port is not None else None
        self.proto     = str(proto)     if proto     is not None else None
        self.flags     = str(flags)     if flags     is not None else None

    def __eq__(self, other):
        if not isinstance(other, Packet):
            return NotImplemented
        return self.src_ip4 == other.src_ip4 and self.dest_ip4 == other.dest_ip4 and self.src_ip6 == other.src_ip6 and \
               self.dest_ip6 == other.dest_ip6 and self.src_mac == other.src_mac and self.dest_mac == other.dest_mac and \
               self.src_port == other.src_port and self.dest_port == other.dest_port and self.proto == other.proto and \
               self.flags == other.flags


def insert_record(p):
    to_db = Communications(p.src_ip4, p.dest_ip4, p.src_ip6, p.dest_ip6, p.src_mac, p.dest_mac,
                           int(p.src_port) if p.src_port is not None else p.src_port,
                           int(p.dest_port) if p.dest_port is not None else p.dest_port, p.proto,
                           p.flags, datetime.datetime.now(), datetime.datetime.now())
    to_db.save()


def update_record_1(p):
    """
    Lo stesso pacchetto è già stato memorizzato, quindi ne aggiorno il timestamp last_seen con questa update
    """
    to_db = Communications.update(
        {Communications.last_seen: datetime.datetime.now()}).where(
            Communications.src_ip4 == p.src_ip4,
            Communications.dest_ip4 == p.dest_ip4,
            Communications.src_ip6 == p.src_ip6,
            Communications.dest_ip6 == p.dest_ip6,
            Communications.src_mac == p.src_mac,
            Communications.dest_mac == p.dest_mac,
            Communications.src_port == p.src_port,
            Communications.dest_port == p.dest_port,
            Communications.proto == p.proto,
            Communications.flags == p.flags
    )

    to_db.execute()


def update_record_2(p):
    """
    I dispositivi hanno già comunicato sulla stessa dest_port, quindi ignoro la src_port e aggiorno il timestamp
    """
    to_db = Communications.update(
        {Communications.last_seen: datetime.datetime.now()}).where(
            Communications.src_ip4   == p.src_ip4,
            Communications.dest_ip4  == p.dest_ip4,
            Communications.src_ip6   == p.src_ip6,
            Communications.dest_ip6  == p.dest_ip6,
            Communications.src_mac   == p.src_mac,
            Communications.dest_mac  == p.dest_mac,
            Communications.dest_port == p.dest_port,
            Communications.proto     == p.proto,
            Communications.flags     == p.flags,
    )

    to_db.execute()


def update_record_3(p):
    """
    I dispositivi hanno già comunicato sulla stessa src_port, quindi ignoro la dest_port e aggiorno il timestamp
    """
    to_db = Communications.update(
        {Communications.last_seen: datetime.datetime.now()}).where(
            Communications.src_ip4  == p.src_ip4,
            Communications.dest_ip4 == p.dest_ip4,
            Communications.src_ip6  == p.src_ip6,
            Communications.dest_ip6 == p.dest_ip6,
            Communications.src_mac  == p.src_mac,
            Communications.dest_mac == p.dest_mac,
            Communications.src_port == p.src_port,
            Communications.proto    == p.proto,
            Communications.flags    == p.flags,
    )

    to_db.execute()


def check_packet(packet):
    """
    0 = Aggiungi il pacchetto
    1 = Aggiorna il timestamp perchè il pacchetto esiste già
    2 = Aggiorna il timestamp perchè hanno già comunicato sulla stessa dest_port
    3 = Aggiorna il timestamp perchè hanno già comunicato sulla stessa src_port
    """

    if packet in packets:
        return 1, "Il pacchetto esiste già"

    for x in packets:
        if x.dest_port == packet.dest_port and x.src_ip4 == packet.src_ip4 and x.dest_ip4 == packet.dest_ip4 and x.proto == packet.proto:
            return 2, "I due dispositivi hanno già comunicato con lo stesso protocollo su questa dest_port"

    for x in packets:
        if x.src_port == packet.src_port and x.src_ip4 == packet.src_ip4 and x.dest_ip4 == packet.dest_ip4 and x.proto == packet.proto:
            return 3, "I due dispositivi hanno già comunicato con lo stesso protocollo su questa src_port"

    return 0, "Pacchetto nuovo"


def print_packet_custom(packet):
    print("{} {} {} {} {} {} {}".format(packet.src_ip4, packet.dest_ip4, packet.src_mac, \
        packet.dest_mac, packet.src_port, packet.dest_port, packet.proto))


def start_sniffing():
    print("start sniffing")
    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
        for packet in capture.sniff_continuously(packet_count=500000):
            src_ip4   = None
            dest_ip4  = None
            src_ip6   = None
            dest_ip6  = None
            src_mac   = None
            dest_mac  = None
            src_port  = None
            dest_port = None
            proto     = None
            flags     = None

            proto = packet.layers[-1]._layer_name

            if proto == "fake-field-wrapper":
                proto = packet.layers[-2]._layer_name
            elif proto == "_ws.malformed":
                continue

            if 'eth' in packet:
                src_mac = packet.eth.src
                dest_mac = packet.eth.dst
            if 'arp' in packet:
                src_mac = packet.arp.src_hw_mac
                dest_mac = packet.arp.dst_hw_mac
                src_ip4 = packet.arp.src_proto_ipv4
                dest_ip4 = packet.arp.dst_proto_ipv4
            elif 'ip' in packet:
                src_ip4 = packet.ip.src
                dest_ip4 = packet.ip.dst
                flags = packet.ip.flags
            elif 'ipv6' in packet:
                src_ip6 = packet.ipv6.src
                dest_ip6 = packet.ipv6.dst
            if 'tcp' in packet:
                src_port = packet.tcp.srcport
                dest_port = packet.tcp.dstport
                flags = packet.tcp.flags
            elif 'udp' in packet:
                src_port = packet.udp.srcport
                dest_port = packet.udp.dstport
            

            pk = Packet(src_ip4, dest_ip4, src_ip6, dest_ip6, src_mac, dest_mac, src_port, dest_port, proto, flags)
            my_check, reason = check_packet(pk)
            if my_check == 0:
                insert_record(pk)
                packets.append(pk)
            else:
                if my_check == 1:
                    update_record_1(pk)
                elif my_check == 2:
                    update_record_2(pk)
                elif my_check == 3:
                    update_record_3(pk)

    except KeyboardInterrupt:
        capture.close()

    except Exception as e:
        f = open("~/pysharkAC/exception.txt", "a")
        f.write(str(e))
        f.close()

    finally:
        capture.close()

    return True


if __name__ == '__main__':
    db.connect()
    packets_in_db = Communications.select()

    for pk in packets_in_db:
        packets.append(Packet(pk.src_ip4, pk.dest_ip4, pk.src_ip6, pk.dest_ip6, pk.src_mac, pk.dest_mac, pk.src_port, pk.dest_port, pk.proto, pk.flags))

    print("Caricati i dati dal database.")

    while start_sniffing():
        pass
