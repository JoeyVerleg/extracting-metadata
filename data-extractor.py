import sys
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.tls.all import *

def getDnsQueries():
        packets = sniff(lfilter = lambda x: x.haslayer(DNS), offline="extracting-metadata/capture_tls.pcap")
        for p in packets:
                print(p.qd.qname)


def getClientHellos():
        myfilter = 'tcp'
        packets = sniff(lfilter=lambda x: TLS in x, filter=myfilter, offline="extracting-metadata/capture_tls.pcap")
        for p in packets:
                if(p.haslayer(TLS_Ext_ServerName)):
                        serverName = p.getlayer(TLS_Ext_ServerName).servernames
                        print(serverName)

getClientHellos()
getDnsQueries()

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