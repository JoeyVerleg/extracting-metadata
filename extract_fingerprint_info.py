import os
import argparse
from data_extractor import DataExtractor

parser = argparse.ArgumentParser(description='Optional app description')
parser.add_argument('tracedir', type=str, help='path to directory of trace files') 
parser.add_argument('outputdir', type=str, help='path to output directory') 
parser.add_argument('local_ip', type=str, help='local ip address') 
args = parser.parse_args()

TRACE_DIR_PATH = args.tracedir
OUTPUT_FILE_PATH = args.outputdir
LOCAL_IP = args.local_ip

extractor = DataExtractor(TRACE_DIR_PATH, OUTPUT_FILE_PATH, LOCAL_IP)
extractor.start_extracting()