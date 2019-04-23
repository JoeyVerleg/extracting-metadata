import os
import argparse
import shutil

parser = argparse.ArgumentParser(description='Can be used for renaming features after they have been grouped by ip adresses which causes them to have missing ranked filenames, this tool renames the files so that there is an order from 0 till 100 without missing numbers' ) 
parser.add_argument('dir', type=str, help='path to directory of files') 
args = parser.parse_args()

DIR_PATH = args.dir

directory = os.fsencode(DIR_PATH)
counter = [0] * 100


for file in os.listdir(directory):
    file_name = os.fsdecode(file)
    file_path = os.path.join(DIR_PATH, os.fsdecode(file))

    index = file_name.split('-')[0]
    new_name = str(index) + '-' + str(counter[int(index)])
    output_directory = os.path.join(DIR_PATH, "output")
    if not os.path.isdir(output_directory):
        os.makedirs(output_directory)
    output_file_path = os.path.join(output_directory, new_name)
    shutil.move(file_path, output_file_path)

    counter[int(index)] += 1

