from opensearch_sdk_py.rest.extension_rest_request import ExtensionRestRequest
from opensearch_sdk_py.rest.extension_rest_response import ExtensionRestResponse 
from opensearch_sdk_py.rest.rest_status import RestStatus 



class DetectorPreviewingHandler(): 
    def handle_preview_detector_request(rest_request: ExtensionRestRequest) -> ExtensionRestResponse: 
        response_bytes = bytes(f"DetectorPreviewingHandler", "utf-8")
        return ExtensionRestResponse(rest_request, RestStatus.OK, response_bytes, ExtensionRestResponse.TEXT_CONTENT_TYPE) 