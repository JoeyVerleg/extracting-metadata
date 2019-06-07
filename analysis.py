import os
import argparse
import shutil
from random import randint

parser = argparse.ArgumentParser(description='Used for applying countermeasures to extracted fingerprints' ) 
parser.add_argument('dir', type=str, help='path to directory of files') 

args = parser.parse_args()

DIR_PATH = args.dir
directory = os.fsencode(DIR_PATH)

def get_size(line):
    return int(line.split('\t')[-1])

total_bandwitdh_in = 0
total_bandwitdh_out = 0
total_packets_in = 0
total_packets_out = 0
amount_files = 0
total_unique_sizes = 0 #the amount of unique packet sizes per file summes, divide by total files to get average unique sizes per file

for file in os.listdir(directory):
    file_name = os.fsdecode(file)
    file_path = os.path.join(DIR_PATH, os.fsdecode(file))
    lines = open(file_path, 'r').readlines()

    sizes = list()
    amount_files = amount_files + 1
    for i, line in enumerate(lines):
        size = get_size(line)
        if size < 0:
            total_bandwitdh_in = total_bandwitdh_in + size
            total_packets_in = total_packets_in + 1
        else:
            total_bandwitdh_out = total_bandwitdh_out + size
            total_packets_out = total_packets_out + 1
        sizes.append(size)
    unique_sizes = len(set(sizes)) #use a set to remove duplicates, and then the len function to count the elements in the set:
    total_unique_sizes = total_unique_sizes + unique_sizes

print("Average values per file:")
print("Total files: " + str(amount_files))
print("Total data in: " + str(total_bandwitdh_in / amount_files))
print("Total data out: " + str(total_bandwitdh_out / amount_files))
print("Total bandwidth: " + str((abs(total_bandwitdh_out) + abs(total_bandwitdh_in)) / amount_files))
print("Total packets in: " + str(total_packets_in / amount_files))
print("Total packets out: " + str(total_packets_out / amount_files))
print("Total packets: " + str((total_packets_out + total_packets_in) / amount_files))
print("unique packet sizes: " + str(total_unique_sizes / amount_files))
    