import pyshark
from peewee import *
from playhouse.db_url import connect
import datetime
import configparser

db = connect('mysql://username:password@localhost:3306/ip')

common_ports = [22, 53, 80, 443]
my_ip_addresses4 = []
my_ip_addresses6 = []
# Quello che viene dall'esterno va catalogato tutto, quello che esce dall'interno (dal mio IP) posso catalogarlo una
# volta sola (es. memorizzo 1 volta sola che ha comunicato con www.google.com sulla porta 443)
packets = []
verbose = 0
more_verbose = 0
interface = 'enp0s3'
bpf_filter = None
output_file = None


def parse_config():
    global common_ports, my_ip_addresses4, my_ip_addresses6, verbose, more_verbose, \
        interface, bpf_filter, output_file
    try:
        config = configparser.ConfigParser(converters={'list': lambda x: [i.strip() for i in x.split(',')]})
        config.read('config.cfg')
        common_ports = [int(x) for x in config.getlist('DEFAULT', 'common_ports')]
        my_ip_addresses4 = config.getlist('DEFAULT', 'my_ip_addresses4')
        my_ip_addresses6 = config.getlist('DEFAULT', 'my_ip_addresses6')
        verbose = True if int(config['DEFAULT']['verbose']) == 1 else False
        more_verbose = True if int(config['DEFAULT']['more_verbose']) == 1 else False
        interface = config['DEFAULT']['interface']
        bpf_filter = config['DEFAULT']['bpf_filter']
        output_file = config['DEFAULT']['output_file']
        print("Config file loaded successfully.")
        return True
    except:
        print("Error reading config file!")
        return False


class BaseModel(Model):
    class Meta:
        database = db


# Database structure for peewee
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


def update_record(p):
    # to_db = Communications(p.src_ip4, p.dest_ip4, p.src_ip6, p.dest_ip6, p.src_mac, p.dest_mac,
    #                       int(p.src_port) if p.src_port is not None else p.src_port,
    #                       int(p.dest_port) if p.dest_port is not None else p.dest_port, p.proto, p.flags)

    to_db = Communications.update({Communications.last_seen: datetime.datetime.now()}).where(
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


def check_packet(packet):
    """
    True = aggiungi il pacchetto, False = aggiornane il timestamp
    """
    if len(packets) == 0:
        return True, "Aggiunto"

    if packet in packets:
        return False, "Il pacchetto esiste già"

    # Questa condizione, nel 99% dei casi, non avviene perchè viene semplicemente trovato il pacchetto nella lista dei
    # pacchetti (controllo precedente a questo). Meglio, perchè questo è molto costoso
    if packet.src_ip4 in my_ip_addresses4 or packet.src_ip6 in my_ip_addresses6:
        if packet.dest_port in common_ports:
            if packet.dest_ip4 in [x.dest_ip4 for x in packets if x.src_ip4 in my_ip_addresses4] or \
                    packet.dest_ip6 in [x.dest_ip6 for x in packets if x.src_ip6 in my_ip_addresses6]:
                return False, "Comunicazione in uscita già memorizzata"

    return True, "Aggiunto"


def print_packet_custom(packet):
    print("{} {} {} {} {} {} {}".format(packet.src_ip4, packet.dest_ip4, packet.src_mac, packet.dest_mac,
                                        packet.src_port, packet.dest_port, packet.proto))


def start_sniffing():
    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter, output_file=output_file)
        # capture = pyshark.FileCapture('pcap/capture50MB.pcap')  # Prima del 50MB: 1376 record

        # capture.set_debug()

        for packet in capture.sniff_continuously():
            # for i, packet in enumerate(capture):
            percent = round(((i / 366410) * 100), 2)
            print(f"[{percent} %] Pacchetto {i}")
            src_ip4 = None
            dest_ip4 = None
            src_ip6 = None
            dest_ip6 = None
            src_mac = None
            dest_mac = None
            src_port = None
            dest_port = None
            proto = None
            flags = None

            # print("---------------------------------------------------------------")
            # print("Captured:")
            layer_name = packet.layers[-1]._layer_name
            # L'ultimo livello, tipicamente quello di interesse
            # Es. nel caso di Modbus/TCP: Ethernet -> IP -> TCP -> *Modbus*

            if layer_name == "fake-field-wrapper":
                continue  # Ignorare. Da quanto ho capito è un campo creato da tshark/wireshark
                # per mantenere una certa struttura dell'output.
            if "_ws.malfor" in layer_name:
                continue  # Devo capire cosa significa, ma probabilmente è un errore nel riconoscimento
                # del protocollo. Comunque, per ora, l'ho visto succedere solo nelle comunicazioni
                # verso 244.0.0.1, ossia Multicast IP.

            proto = layer_name
            flags = None
            # print(packet.layers[-1])
            # print(packet)
            # print("-   -   -   -   -   -   -   -   -   -   -   -   -   -   -   -")

            if 'eth' in packet:
                src_mac = packet.eth.src
                dest_mac = packet.eth.dst
                if more_verbose:
                    print("ETH:")
                    print(f"src_mac: {packet.eth.src}, dest_mac: {packet.eth.dst}")
            if 'arp' in packet:
                src_mac = packet.arp.src_hw_mac
                dest_mac = packet.arp.dst_hw_mac
                src_ip4 = packet.arp.src_proto_ipv4
                dest_ip4 = packet.arp.dst_proto_ipv4
                if more_verbose:
                    print("ARP:")
                    print(
                        f"src_mac: {packet.arp.src_hw_mac}, dest_mac: {packet.arp.dst_hw_mac}, Opcode: {'Request' if int(packet.arp.opcode) == 1 else 'Reply' if int(packet.arp.opcode) == 2 else 'Unknown'}")  # Opcode: 1 = request, 2 = reply
            elif 'ip' in packet:
                src_ip4 = packet.ip.src
                dest_ip4 = packet.ip.dst
                flags = packet.ip.flags
                if more_verbose:
                    print("IPv4:")
                    print(f"src_ip4: {packet.ip.src}, dest_ip4: {packet.ip.dst}, flags: {packet.ip.flags}")
            elif 'ipv6' in packet:
                src_ip6 = packet.ipv6.src
                dest_ip6 = packet.ipv6.dst
                # IPv6 non ha flags.
                if more_verbose:
                    print("IPv6:")
                    print(f"src_ip6: {packet.ipv6.src}, dest_ip6: {packet.ipv6.dst}")
            if 'tcp' in packet:
                src_port = packet.tcp.srcport
                dest_port = packet.tcp.dstport
                flags = packet.tcp.flags
                if more_verbose:
                    print("TCP:")
                    print(f"srcport: {packet.tcp.srcport}, destport: {packet.tcp.dstport}")
            elif 'udp' in packet:
                src_port = packet.udp.srcport
                dest_port = packet.udp.dstport
                if more_verbose:
                    print("UDP:")
                    print(f"srcport: {packet.udp.srcport}, destport: {packet.udp.dstport}")

            # Altri protocolli non dovrebbero modificare le informazioni che abbiamo deciso di memorizzare,
            # quindi non è necessario verificarne il contenuto. L'unico dato che cambia è, appunto, il nome
            # del protocollo, che viene settato prima di questa catena if/elif. Se poi si vorranno estrarre
            # ulteriori contenuti dei pacchetti per determinati protocolli sarà comunque possibile farlo.

            # if 'modbus' in packet:
            #    print("Captured:", packet.modbus.pretty_print())
            # else:
            #    print("Captured:", packet)

            # print(type(src_ip4), type(dest_ip4), type(src_ip6), type(dest_ip6), type(src_mac), type(dest_mac), type(src_port), type(dest_port), type(proto), type(flags))

            src_ip4 = str(src_ip4) if src_ip4 is not None else None
            dest_ip4 = str(dest_ip4) if dest_ip4 is not None else None
            src_ip6 = str(src_ip6) if src_ip6 is not None else None
            dest_ip6 = str(dest_ip6) if dest_ip6 is not None else None
            src_mac = str(src_mac) if src_mac is not None else None
            dest_mac = str(dest_mac) if dest_mac is not None else None
            src_port = int(src_port) if src_port is not None else None
            dest_port = int(dest_port) if dest_port is not None else None
            proto = str(proto) if proto is not None else None
            flags = str(flags) if flags is not None else None

            pk = Packet(src_ip4, dest_ip4, src_ip6, dest_ip6, src_mac, dest_mac, src_port, dest_port, proto, flags)
            my_check, reason = check_packet(pk)
            if my_check:
                insert_record(pk)
                packets.append(pk)
                if verbose:
                    print("Pacchetto inserito:")
                    print_packet_custom(pk)
            else:
                update_record(pk)
                if verbose:
                    print(f"Aggiornato il timestamp, {reason}:")
                    print_packet_custom(pk)

    except KeyboardInterrupt:
        capture.close()


if __name__ == '__main__':
    if not parse_config():
        exit()

    db.connect()
    packets_in_db = Communications.select()  # .execute()
    # packets = list(packets_in_db)

    # In questo modo sono sicuro che packets sia una lista di oggetti Packet
    for pk in packets_in_db:
        # print(pk.src_ip4, pk.dest_ip4, pk.src_ip6, pk.dest_ip6, pk.src_mac, pk.dest_mac, pk.src_port, pk.dest_port, pk.proto, pk.flags)
        packets.append(
            Packet(pk.src_ip4, pk.dest_ip4, pk.src_ip6, pk.dest_ip6, pk.src_mac, pk.dest_mac, pk.src_port, pk.dest_port,
                   pk.proto, pk.flags))

    # print("- - - - - - - - - - - - - - - - - - - - - -")
    # for pk in packets:
    #    print(pk.src_ip4, pk.dest_ip4, pk.src_ip6, pk.dest_ip6, pk.src_mac, pk.dest_mac, pk.src_port, pk.dest_port, pk.proto, pk.flags)

    print("-----------------------------------------")
    print("--------Letti i dati dal database--------")

    # for pk in packets:
    #    print(pk.src_ip4, pk.dest_ip4, pk.src_ip6, pk.dest_ip6, pk.src_mac, pk.dest_mac, pk.src_port, pk.dest_port, pk.proto, pk.flags)
    #    print(type(pk))

    start_sniffing()

    # print("-----------------------------------------")
    # print("---Dump della lista packets---")
    # for pk in packets:
    #    print(pk)
