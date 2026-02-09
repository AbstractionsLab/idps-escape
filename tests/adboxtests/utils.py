import os
from adbox.data_manager.data_storage_manager import DataStorageManager
from adbox.settings import DETECTOR_FOLDER

KEEP_ASSETS=False # if False the assets generated during every test are removed 
PERSISTENT_DETECTORS_IDS=['2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95','cf6e38ba-2cc0-41e1-b2bc-9072d80284fa','7f240591-3b5b-4cc8-91fe-09ce51f7ff85']

def file_exists(directory, filename):
    file_path = os.path.join(directory, filename)
    return os.path.exists(file_path)

def rm_detector_folder():
        dsm=DataStorageManager()
        id=dsm.uuid
        if id not in PERSISTENT_DETECTORS_IDS:
            directory=DETECTOR_FOLDER.format(id=dsm.uuid)
            os.system("rm -r "+directory)

def rm_detector_folder_from_id(id):
        if id not in PERSISTENT_DETECTORS_IDS:
            directory=DETECTOR_FOLDER.format(id=id)
            os.system("rm -r "+directory)            