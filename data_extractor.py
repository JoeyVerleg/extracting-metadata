import sys
import argparse
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.tls.all import *
from scapy.layers.inet import *
from collections import defaultdict

class DataExtractor:
    CAPTURE_FILTER = ""

    def __init__(self, trace_dir, output_dir, local_ip):
        load_layer("tls")
        self.TRACE_DIR = trace_dir
        self.OUTPUT_DIR = output_dir
        self.LOCAL_IP = local_ip
        self.dns_dict = dict()
        self.client_hello_dict = dict()
        self.domain_ip_dict = dict()
          
    def get_dns_responses(self, path_tracefile):
        packets = sniff(lfilter = lambda x: x.haslayer(DNSRR), offline=path_tracefile)
        return packets

    def get_tls_packets(self, path_tracefile):
        packets = sniff(lfilter = lambda x: x.haslayer(TLS), offline=path_tracefile, filter=self.CAPTURE_FILTER)
        return packets
        
    def get_client_hello_packets(self, path_tracefile):
        packets = sniff(lfilter = lambda x: x.haslayer(TLS_Ext_ServerName), offline=path_tracefile)
        return packets

    def get_tcp_packets(self, path_tracefile):
        packets = sniff(lfilter = lambda x: x.haslayer(TCP), offline=path_tracefile, filter=self.CAPTURE_FILTER)
        return packets

    def get_all_packets(self, path_tracefile):
        packets = sniff(offline=path_tracefile) #filter = "host 2.18.169.16"

        return packets

    def get_packet_size(self, packet, protocol):
        # TODO: sometimes there are multiple TLS records into 'one' TLS record
        if protocol == TLS:
            size = packet.getlayer(TLS).len
            # Might contain RAW data which scapy does not understand. TODO check if this data is important
            try:
                while packet.getlayer(TLS).payload:
                    packet = packet.getlayer(TLS).payload
                    size += packet.len
                return size
            except AttributeError:
                return size
        elif protocol == TCP:
            layer = packet.getlayer(TCP)
            return len(layer)

    def get_client_hello_servername(self, packet):
            if(packet.haslayer(TLS_Ext_ServerName)):
                serverNames = getattr(packet.getlayer(TLS_Ext_ServerName), 'servernames') #TODO check when there are multiple server names in the client hello message
                if serverNames:
                    return serverNames[0].servername.decode("utf-8")

    def get_tls_packet_fingerprint_info(self, packet, relative_time):
        """ Returns size timing direction of TLS packet """

        size = self.get_packet_size(packet, TLS)
        time = packet.time - relative_time
        direction = self.get_packet_direction(packet)
        return str(time) + '\t' + str(direction*size)

    def get_tcp_packet_fingerprint_info(self, packet, relative_time):
        """ Returns size timing direction of TCP packet """

        size = self.get_packet_size(packet, TCP)
        time = packet.time - relative_time
        direction = self.get_packet_direction(packet)
        return str(time) + '\t' + str(direction*size)

    def get_packet_direction(self, packet):
        """ Returns the direction of the packet, +1 indicaties outgoing, -1 incoming """

        src = packet.getlayer(IP).src
        if src == self.LOCAL_IP:
            return 1
        return -1

    def reverse_dict_key(self, key):
        """ Reverse a given key 'TCP 172.217.17.102:443 > 10.7.2.60:38386'
            into 'TCP 10.7.2.60:38386 > 172.217.17.102:443'
        """
        result = key.split(' ')
        src = result[1]
        dst = result[3]
        result[1] = dst
        result[3] = src
        return " ".join(result)

    def group_packets(self, packets):
        """ Returns a list of PacketLists
            All connections from X to Y and from Y to X are grouped in each PacketList
        """
        sessions = packets.sessions() # groups connections from X to Y as a Scapy PacketList in a dict
        # example: dict['TCP 172.217.17.102:443 > 10.7.2.60:38386'] = PacketList

        session_keys = list(sessions.keys()) # force copy so we can alter the dictionary at runtime
        for key in session_keys:
            reversed_key = self.reverse_dict_key(key)
            if(reversed_key != key and sessions.__contains__(reversed_key)):
                sessions[key] += sessions.pop(reversed_key)
                session_keys.remove(reversed_key)

        return self.sort_grouped_packets(list(sessions.values()))

    def sort_grouped_packets(self, grouped_packets):
        """ Sorts all packets based on time send from first to last """
        for group in grouped_packets:
            group.sort(key=lambda x: x.time, reverse=False)
        return grouped_packets

    def create_dns_dictionary(self, path_tracefile):
        """ Create a dictionary based on DNS information mapping all IP adresses to domain names
            example: dict['172.217.19.196'] = 'www.google.com'
        """
        responses = self.get_dns_responses(path_tracefile)
        dns_dict = dict()
        for response in responses:
            for x in range(response[DNS].ancount): # answer count, how many IP adresses are returned for the query
                try: # answer count could also include 'DNS SRV Resource Record' which does not have a 'rrname' attribute so ancount is wrong if there is such a record -> TODO get amount of DNSRR instead of using ancount
                    domain = getattr(response[DNSRR][x], 'rrname').decode("utf-8") # domain (this is returned in bytes so decode)
                    ip = getattr(response[DNSRR][x], 'rdata') # IP adres of the domain, TODO make this work for multiple ip adresses for one domain (Test with [0] at end)
                    dns_dict[ip] = domain[:-1] #remove last char '.' 
                except:
                    continue
        return dns_dict

    def create_client_hello_dictionary(self, path_tracefile):
        """ Create a dictionary based on SNI information mapping all IP adresses to domain names
            example: dict['172.217.19.196'] = 'www.google.com'
        """
        packets = self.get_client_hello_packets(path_tracefile)
        client_hello_dict = dict()
        for packet in packets:
            servername = self.get_client_hello_servername(packet)
            if servername:
                ip = packet.getlayer(IP).dst
                client_hello_dict[ip] = servername
        return client_hello_dict
    
    def get_domain_ip_via_sni(self, path_tracefile, domain):
        """ Return the ip address for the provided domain by searching in the SNI extensions in the tracefile """
        packets = self.get_client_hello_packets(path_tracefile)
        for packet in packets:
            servername = self.get_client_hello_servername(packet)
            if servername == domain:
                ip = packet.getlayer(IP).dst
                return ip
        return -1

        
    def print_packet(self, packet, relative_time):
        """ Used for debugging """
        protocol = ""
        size = 0
        if packet.haslayer(TCP):
            protocol += "TCP / "
            src = packet.getlayer(IP).src
            src_port = str(packet.getlayer(TCP).sport)

            dst = packet.getlayer(IP).dst
            dst_port = str(packet.getlayer(TCP).dport)

            if self.domain_ip_dict.__contains__(src):
                src = self.domain_ip_dict.get(src)
            if self.dns_dict.__contains__(dst):
                dst = self.domain_ip_dict.get(dst)
            size = self.get_packet_size(packet, TCP)
        else:
            return
        if packet.haslayer(TLS):
            protocol += "TLS / "
            size = self.get_packet_size(packet, TLS)
        result = protocol + src + ":" + src_port + " > " + dst + ":" + dst_port + " / Size " + str(size) + " / " + str(packet.time - relative_time)
        # print(result)
        return result

    def print_group_packets(self, group):
        """ Used for debugging """

        relative_time = group[0].time
        for packet in group:
            self.print_packet(packet, relative_time)

    def save_as_fingerprint(self, packets, file_path):
        """ Saves a packetlist as a fingerprint 
            timing <tab> direction size
            example: 0.32323<tab>-1440
        """
        relative_time = packets[0].time
        with open(file_path, 'a') as out:
            for packet in packets:
                # data = self.get_tcp_packet_fingerprint_info(packet, relative_time)
                data = self.get_tls_packet_fingerprint_info(packet, relative_time)
                out.write(data + '\n')


    def set_filter(self, filter):
        self.CAPTURE_FILTER = filter
        
    def start_extracting(self):
        # if MAP_DOMAINS:
            # dns_dict = create_dns_dictionary()
            # client_hello_dict = create_client_hello_dictionary()
            # domain_ip_dict = {**dns_dict, **client_hello_dict} #merge dictionaries
        # if GROUPED    
            # save as grouped
        directory = os.fsencode(self.TRACE_DIR)
        for file in os.listdir(directory):
            trace_file_path = os.path.join(self.TRACE_DIR, os.fsdecode(file))
            fingerprint_file_path = os.path.join(self.OUTPUT_DIR, os.fsdecode(file).split('.pcap')[0])
            print(trace_file_path)
            # ip_imdb = self.get_domain_ip_via_sni(trace_file_path, "www.imdb.com")
            # # self.CAPTURE_FILTER = "host " + ip_imdb
            # if ip_imdb != "52.85.245.38":
            #     continue
            # self.CAPTURE_FILTER = "host 52.85.245.38"
            # packets = self.get_tcp_packets(trace_file_path)
            packets = self.get_tls_packets(trace_file_path)
            self.save_as_fingerprint(packets, fingerprint_file_path)
