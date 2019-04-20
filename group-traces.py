import os
import argparse
from data_extractor import DataExtractor
import shutil

parser = argparse.ArgumentParser(description='Optional app description')
parser.add_argument('tracedir', type=str, help='path to directory of trace files') 
parser.add_argument('outputdir', type=str, help='path to output directory') 
parser.add_argument('domain', type=str, help='domain of the multiple hosts that need to be grouped by their ip addresses') 
args = parser.parse_args()

TRACE_DIR_PATH = args.tracedir
OUTPUT_DIR_PATH = args.outputdir
DOMAIN = args.domain

extractor = DataExtractor("", "", "")
directory = os.fsencode(TRACE_DIR_PATH)
for file in os.listdir(directory):
    trace_file_path = os.path.join(TRACE_DIR_PATH, os.fsdecode(file))
    ip = extractor.get_domain_ip_via_sni(trace_file_path, DOMAIN)

    output_directory = os.path.join(OUTPUT_DIR_PATH, ip)
    if not os.path.isdir(output_directory):
        os.makedirs(output_directory)
    output_trace_file_path = os.path.join(output_directory, os.fsdecode(file))
    print(output_trace_file_path)
    shutil.move(trace_file_path, output_trace_file_path)


# python3.7 group-traces.py traces_13_04/ output_domain_imdb/ "192.168.191.128"
