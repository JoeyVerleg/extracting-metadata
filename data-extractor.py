import sys
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.tls.all import *
from collections import defaultdict

CAPTURE_FILE_PATH = "/home/joey/Desktop/extracting-metadata/capture_tls.pcap"
CAPTURE_FILTER = "host 2.18.169.16"
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
        return len(layer)

# Match DNS requests with their responses
def match_dns_responses(packets):
    matches = defaultdict(list)
    for p in packets:
        p = p.getlayer(DNS)
        if p.id in matches:
            matches[p.id].append(p)
        else:
            temp_list = list()      
            temp_list.append(p)     
            matches[p.id] = temp_list       
    print(list(matches.items())[6][1][0].show())
    print(list(matches.items())[6][1][1].show())

def get_client_hellos():
    myfilter = 'tcp'
    packets = sniff(lfilter=lambda x: TLS in x, filter=myfilter, offline=CAPTURE_FILE_PATH)
    for p in packets:
        if(p.haslayer(TLS_Ext_ServerName)):
            print(p.show())
            return
            serverName = p.getlayer(TLS_Ext_ServerName).servernames
            # print(serverName)

# Create a DNS dictionary mapping all IP adresses to domains
# example: dict['172.217.19.196'] = 'www.google.com' 
def create_dns_dictionary():
    responses = get_dns_responses()
    dns_dict = dict()
    for response in responses:
        for x in range(response[DNS].ancount): # answer count, how many IP adresses are returned for the query
            domain = getattr(response[DNSRR][x], 'rrname').decode("utf-8") # domain (this is returned in bytes so decode)
            ip = getattr(response[DNSRR][x], 'rdata') # IP adres of the domain
            dns_dict[ip] = domain
    return dns_dict


dns_dict = create_dns_dictionary()
print(dns_dict.items())


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