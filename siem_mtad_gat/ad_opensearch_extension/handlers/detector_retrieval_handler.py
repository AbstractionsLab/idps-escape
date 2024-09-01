from opensearch_sdk_py.rest.extension_rest_request import ExtensionRestRequest
from opensearch_sdk_py.rest.extension_rest_response import ExtensionRestResponse 
from opensearch_sdk_py.rest.rest_status import RestStatus 



class DetectorRetrievalHandler(): 
    def handle_get_detector_request(rest_request: ExtensionRestRequest) -> ExtensionRestResponse: 
        detector_id = rest_request.param("detectorId") 
        print("detector_id: ", detector_id)
        response_bytes = bytes(f"DetectorRetrievalHandler", "utf-8")
        return ExtensionRestResponse(rest_request, RestStatus.OK, response_bytes, ExtensionRestResponse.TEXT_CONTENT_TYPE) 