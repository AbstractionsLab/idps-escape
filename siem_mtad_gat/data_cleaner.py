#!/usr/bin/python3
# This module may require root permission
# sudo poetry run python siem_mtad_gat/data_cleaner.py

import os
import shutil

import siem_mtad_gat.settings as settings
from siem_mtad_gat.shipper.wazuh_data_shipper import WazuhDataShipper


YES='YES'
NO='no'
OPTIONS=f"({YES}/{NO})"

## ASSUMING MTAD-GAT USED
#TO = MAKE GENERIC

# Directory where the subfolders are located
TARGET_DIR: str=settings.DETECTOR_MODELS_STORAGE_FOLDER

# List of subfolders you want to keep (space-separated)
KEEP_DETECTORS: list[str]=settings.KEEP_DETECTORS

def remove_detector_folder(id):
    # Check if the item is a directory and not in the keep list
    if id in KEEP_DETECTORS:
        print(f"Keeping detector's folder. List of protected detectors: {KEEP_DETECTORS}")
        exit()

    folder=settings.DETECTOR_FOLDER.format(id=id)
    print(f"Removing {folder}")
    shutil.rmtree(folder)  # Removes the directory and its contents



def remove_all_detectors():
    removed=[]
    # List all items in the target directory
    for item in os.listdir(TARGET_DIR):
        item_path = os.path.join(TARGET_DIR, item)
        # Check if the item is a directory and not in the keep list
        if os.path.isdir(item_path) and item not in KEEP_DETECTORS:
            print(f"Removing detector's folder: {item}")
            shutil.rmtree(item_path)  # Removes the directory and its contents
            removed+=[item]
        else:
            print(f"Keeping detector's folder: {item}")
    return removed

def remove_detector_stream(id,wds):
    wds.delete_data_stream(id)

    

def check_option(s):
    if s not in [YES,NO]:
        raise Exception(f"Answer NOT valide! Choose {OPTIONS}.")
    
def sure():
    s=input(f"Sure? {OPTIONS}: ")
    if s == NO: exit()

def main():
    print("Attention: deletion of a detector folder/stream is irreversible!")
    print("Answers to the following questions are case sensitive.")
    remove_specific = input(f"Do you want to remove a specific detector? {OPTIONS}: ")
    check_option(remove_specific)

    if remove_specific == YES:
        detector_id = input("Enter the detector uuid (e.g.,dac98b33-6aa1-43de-a5ef-7bbcf7fff430):  ").lower()
        remove_detector_folder(detector_id)
        remove_stream = input(f"Do you want to remove the corresponding detector stream? {OPTIONS}: ")
        check_option(remove_stream)
        if remove_stream == YES:
            wds=WazuhDataShipper(install=True)
            remove_detector_stream(detector_id,wds=wds)
    else:
        remove_all = input(f"Do you want to remove all detectors? {OPTIONS}: ")
        check_option(remove_all)
        if remove_all == YES:
            removed=remove_all_detectors()
            remove_all_streams = input(f"Do you want to remove all corresponding detector streams? {OPTIONS}: ")
            sure()
            check_option(remove_all_streams)
            if remove_all_streams == YES:
                wds=WazuhDataShipper(install=True)
                for uuid in removed: remove_detector_stream(uuid,wds=wds)

    print("Exit.")

if __name__ == "__main__":
    main()