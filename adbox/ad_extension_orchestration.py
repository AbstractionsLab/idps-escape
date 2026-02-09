from opensearch_sdk_py import *   
from adbox.ad_opensearch_extension.handlers.detector_creation_handler import DetectorCreationHandler 



class ADOrchestration:
    """
    Class to handle the orchestration of the anomaly detection extension.
    """

    def __init__(self):
        """
        """ 


if __name__ == "__main__": 
    handler = DetectorCreationHandler() 
    handler.handle_create_detector_request()
