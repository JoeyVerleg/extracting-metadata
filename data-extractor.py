import sys
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.tls.all import *
from collections import defaultdict

CAPTURE_FILE_PATH = "/home/joey/Desktop/extracting-metadata/capture_tls.pcap"
CAPTURE_FILTER = ""
#CAPTURE_FILTER = "host 2.18.169.16"
load_layer("tls")

def get_dns_responses():
    packets = sniff(lfilter = lambda x: x.haslayer(DNSRR), offline=CAPTURE_FILE_PATH)
    return packets

def get_tls_packets():
    packets = sniff(lfilter = lambda x: x.haslayer(TLS), offline=CAPTURE_FILE_PATH)
    return packets

def get_tcp_packets():
    packets = sniff(lfilter = lambda x: x.haslayer(TCP), filter=CAPTURE_FILTER, offline=CAPTURE_FILE_PATH)
    return packets

def get_all_packets():
    packets = sniff(filter=CAPTURE_FILTER, offline=CAPTURE_FILE_PATH)
    return packets

def get_packet_size(packet, protocol):
    # TODO: sometimes there are multiple TLS records into 'one' TLS record
    if protocol == TLS:
        layer = packet.getlayer(TLS)
        return layer.len
    elif protocol == TCP:
        layer = packet.getlayer(TCP)
        return str(len(layer))

def get_client_hellos():
    myfilter = 'tcp'
    packets = sniff(lfilter=lambda x: TLS in x, filter=myfilter, offline=CAPTURE_FILE_PATH)
    for p in packets:
        if(p.haslayer(TLS_Ext_ServerName)):
            print(p.show())
            return
            serverName = p.getlayer(TLS_Ext_ServerName).servernames
            # print(serverName)

def reverse_dict_key(key):
    """ Reverse a given key 'TCP 172.217.17.102:443 > 10.7.2.60:38386'
        into 'TCP 10.7.2.60:38386 > 172.217.17.102:443'
    """
    result = key.split(' ')
    src = result[1]
    dst = result[3]
    result[1] = dst
    result[3] = src
    return " ".join(result)

def group_packets():
    """ Returns a list of PacketLists
        All connections from X to Y and from Y to X are grouped in each PacketList
    """
    packets = get_all_packets()
    sessions = packets.sessions() # groups connections from X to Y as a Scapy PacketList in a dict
    # example: dict['TCP 172.217.17.102:443 > 10.7.2.60:38386'] = PacketList

    session_keys = list(sessions.keys()) # force copy so we can alter the dictionary at runtime
    for key in session_keys:
        reversed_key = reverse_dict_key(key)
        if(reversed_key != key and sessions.__contains__(reversed_key)):
            sessions[key] += sessions.pop(reversed_key)
            session_keys.remove(reversed_key)

    return sort_grouped_packets(list(sessions.values()))

def sort_grouped_packets(grouped_packets):
    """ Sorts all packets based on time send from first to last """
    for group in grouped_packets:
        group.sort(key=lambda x: x.time, reverse=False)
    return grouped_packets

def create_dns_dictionary():
    """ Create a DNS dictionary mapping all IP adresses to domains
        example: dict['172.217.19.196'] = 'www.google.com'
    """
    responses = get_dns_responses()
    dns_dict = dict()
    for response in responses:
        for x in range(response[DNS].ancount): # answer count, how many IP adresses are returned for the query
            domain = getattr(response[DNSRR][x], 'rrname').decode("utf-8") # domain (this is returned in bytes so decode)
            ip = getattr(response[DNSRR][x], 'rdata') # IP adres of the domain
            dns_dict[ip] = domain[:-1] #remove last char '.' 
    return dns_dict

def create_client_hello_dictionary():
    return
    
def print_packet(packet):
    if packet.haslayer(TCP):
        src = packet.getlayer(IP).src
        src_port = str(packet.getlayer(TCP).sport)

        dst = packet.getlayer(IP).dst
        dst_port = str(packet.getlayer(TCP).dport)

        if dns_dict.__contains__(src):
            src = dns_dict.get(src)
        if dns_dict.__contains__(dst):
            dst = dns_dict.get(dst)

        print("TCP / " 
                + src + ":" + src_port
                + " > " 
                + dst + ":" + dst_port
                + " / Size " + get_packet_size(packet, TCP)
                + " / " + str(packet.time))
    return

dns_dict = create_dns_dictionary()
client_hello = create_client_hello_dictionary()
grouped_packets = group_packets()
for group in grouped_packets:
    for packet in group:
        print_packet(packet)

# print(get_packet_size(tls_packets[13], TLS))
# print(get_packet_size(tls_packets[13], TCP))
#wireshark client hello filter:
#ssl.handshake.extensions_server_name

#python3 -m pip install scapy
# verbinding dns request linken aan connecties: timing tls record, begin tcp connect en ook size tcp record
# start/begin 
# visualisatie achteraf
# literatuurstudie goed bijhouden, ook geencrypteerde vormen aanhalen (is hier nog metadata uit te halen?), http3 iets uit zeggen (is al voorbeeld geven)
# tls->sni waarom, dns niet te basic uitleggen
# linken leggen tussen huidige implementaties en nieuwere (HTTP3)
# timing begin stopt, sizes,  

# tcp connecties samenvoegen adhv session ids?

#TODO: handshake herkennen waar deze start en eindigt?