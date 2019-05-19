import os
import argparse
import shutil
from random import randint

parser = argparse.ArgumentParser(description='Used for applying countermeasures to extracted fingerprints' ) 
parser.add_argument('dir', type=str, help='path to directory of files') 
parser.add_argument('outputdir', type=str, help='path to output directory of files') 
parser.add_argument('countermeasure', type=str, help='the countermeasure to apply, session random padding = session, packet random padding = packet, tor sizes (all 1) = tor') 

args = parser.parse_args()

DIR_PATH = args.dir
OUTPUT_DIR_PATH = args.outputdir
COUNTERMEASURE = args.countermeasure

directory = os.fsencode(DIR_PATH)
if not os.path.isdir(OUTPUT_DIR_PATH):
    os.makedirs(OUTPUT_DIR_PATH)

def session_random_padding(lines):
    ''' 
    A  uniform value r {0,8,16...,248} is sampled and stored for the session.
    Each packet in the trace has its length field increased by r,up to a maximum of the MTU.
    '''
    r = randint(0, 248)
    for i, line in enumerate(lines):
        old_size = abs(get_size(line))
        new_size = old_size + r # add random
        lines[i] = line.replace(str(old_size) + '\n', str(new_size) + '\n')
    return lines

def packet_random_padding(lines):
    ''' 
    Same  as  Session  Random 255 padding,
    except that a new random padding length r is sampled for each input packet
    '''
    for i, line in enumerate(lines):
        old_size = abs(get_size(line))
        new_size = old_size + randint(0, 248) # add random
        lines[i] = line.replace(str(old_size) + '\n', str(new_size) + '\n')
    return lines

def tor_padding(lines):
    ''' 
    Change all packet sizes to 1
    '''

    for i, line in enumerate(lines):
        old_size = abs(get_size(line))
        new_size = 1
        lines[i] = line.replace(str(old_size) + '\n', str(new_size) + '\n')
    return lines

def get_size(line):
    return int(line.split('\t')[-1])

def apply_countermeasure(lines):
    if COUNTERMEASURE == "session":
        lines = session_random_padding(lines)
    elif COUNTERMEASURE == "packet":
        lines = packet_random_padding(lines)
    elif COUNTERMEASURE == "tor":
        lines = tor_padding(lines)
    return lines



for file in os.listdir(directory):
    file_name = os.fsdecode(file)
    file_path = os.path.join(DIR_PATH, os.fsdecode(file))
    output_file_path = os.path.join(OUTPUT_DIR_PATH, file_name)

    lines = open(file_path, 'r').readlines()
    lines = apply_countermeasure(lines)
    out = open(output_file_path, 'w')
    print(output_file_path)
    out.writelines(lines)
    out.close()