import os
import argparse
from data_extractor import DataExtractor

parser = argparse.ArgumentParser(description='Optional app description')
parser.add_argument('tracedir', type=str, help='path to directory of trace files') 
parser.add_argument('outputdir', type=str, help='path to output directory') 
parser.add_argument('local_ip', type=str, help='local ip address') 
parser.add_argument('filter', type=str, help='filter for scapy sniffer function') 
parser.add_argument('type', type=str, help='type of packets to extract, tcp, tls') 
args = parser.parse_args()

TRACE_DIR_PATH = args.tracedir
OUTPUT_FILE_PATH = args.outputdir
LOCAL_IP = args.local_ip
FILTER = args.filter
TYPE = args.type

extractor = DataExtractor(TRACE_DIR_PATH, OUTPUT_FILE_PATH, LOCAL_IP, TYPE)
extractor.set_filter(FILTER)
extractor.start_extracting()

#IMDB IP: 52.85.245.38 or 54.192.15.64
# python3.7 extract_fingerprint_info.py traces_13_04/ output_domain_imdb/ "192.168.191.128"