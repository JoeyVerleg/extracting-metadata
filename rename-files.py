import os
import argparse
import shutil

parser = argparse.ArgumentParser(description='Can be used for renaming features after they have been grouped by ip adresses which causes them to have missing ranked filenames, this tool renames the files so that there is an order from 0 till 100 without missing numbers' ) 
parser.add_argument('dir', type=str, help='path to directory of files') 
parser.add_argument('outputdir', type=str, help='path to output directory of renamed files') 
parser.add_argument('amount', type=int, help='amount of files to copy and rename') 
parser.add_argument('startvalue', type=int, help='start value of file name indices') 

args = parser.parse_args()

DIR_PATH = args.dir
OUTPUT_DIR_PATH = args.outputdir
AMOUNT = args.amount
STARTVALUE = args.startvalue
MAXPAGES = 100

directory = os.fsencode(DIR_PATH)
counter = [0] * MAXPAGES
if not os.path.isdir(OUTPUT_DIR_PATH):
    os.makedirs(OUTPUT_DIR_PATH)

for file in os.listdir(directory):
    file_name = os.fsdecode(file)
    file_path = os.path.join(DIR_PATH, os.fsdecode(file))

    index = file_name.split('-')[0]
    new_value = counter[int(index)]
    if new_value >= AMOUNT:
        continue
    new_name = str(index) + '-' + str(new_value + STARTVALUE)
    output_file_path = os.path.join(OUTPUT_DIR_PATH, new_name)
    shutil.copy(file_path, output_file_path)
    print(file_path)
    print(output_file_path)
    counter[int(index)] += 1
