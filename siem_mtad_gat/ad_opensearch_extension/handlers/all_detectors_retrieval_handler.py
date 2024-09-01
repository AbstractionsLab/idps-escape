from opensearch_sdk_py.rest.extension_rest_request import ExtensionRestRequest
from opensearch_sdk_py.rest.extension_rest_response import ExtensionRestResponse 
from opensearch_sdk_py.rest.rest_status import RestStatus 
from siem_mtad_gat.data_manager.detectors import retrieve_all_detector_parameters 
import siem_mtad_gat.settings as settings

class AllDetectorsRetrievalHandler(): 
    def handle_get_all_detectors_request(rest_request: ExtensionRestRequest) -> ExtensionRestResponse: 
        
        detectors = retrieve_all_detector_parameters() 
        
        print(detectors)  
        
        #headers: dict[str, list[str]] = dict() 
        
        # response_headers = {
        # "Access-Control-Allow-Origin": "*",
        # #"Access-Control-Allow-Headers": "Content-Type,Authorization",
        # #"Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS",
        # }      
        
        # response_headers = {
        # "Access-Control-Allow-Origin": ["*"],
        # "Access-Control-Allow-Headers": ["Content-Type", "Authorization"],
        # "Access-Control-Allow-Methods": ["GET", "PUT", "POST", "DELETE", "OPTIONS"],
        # } 

        response_headers = {
        "Access-Control-Allow-Origin": "*".split(','),
        "Access-Control-Allow-Headers": "Content-Type,Authorization".split(','),
        "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS".split(','),
        }  
        
        
        response_bytes = bytes(f"{detectors}", "utf-8")
        return ExtensionRestResponse(rest_request, RestStatus.OK, response_bytes, ExtensionRestResponse.JSON_CONTENT_TYPE, response_headers) 