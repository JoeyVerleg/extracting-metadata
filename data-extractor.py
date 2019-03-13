import sys
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.tls.all import *
from collections import defaultdict

CAPTURE_FILE_PATH = "/home/joey/Desktop/extracting-metadata/capture_tls.pcap"

def get_dns_packets():
    packets = sniff(lfilter = lambda x: x.haslayer(DNS), offline=CAPTURE_FILE_PATH)
    return packets

def get_tls_packets():
    packets = sniff(lfilter = lambda x: x.haslayer(TLS), offline=CAPTURE_FILE_PATH)
    return packets

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
                        
dns_packets = get_dns_packets()
match_dns_responses(dns_packets)
get_client_hellos()

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
