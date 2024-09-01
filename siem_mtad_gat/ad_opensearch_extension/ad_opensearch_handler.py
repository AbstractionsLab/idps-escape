#!/usr/bin/env python
#
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#


import logging 
import re
from opensearch_sdk_py.rest.extension_rest_handler import ExtensionRestHandler
from opensearch_sdk_py.rest.extension_rest_request import ExtensionRestRequest
from opensearch_sdk_py.rest.extension_rest_response import ExtensionRestResponse
from opensearch_sdk_py.rest.named_route import NamedRoute
from opensearch_sdk_py.rest.rest_method import RestMethod
from opensearch_sdk_py.rest.rest_status import RestStatus 

from siem_mtad_gat.ad_opensearch_extension.handlers.detector_creation_handler import DetectorCreationHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.detector_deletion_handler import DetectorDeletionHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.anomaly_detection_handler import AnomalyDetectionHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.detector_retrieval_handler import DetectorRetrievalHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.detector_previewing_handler import DetectorPreviewingHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.detector_updation_handler import DetectorUpdationHandler 
from siem_mtad_gat.ad_opensearch_extension.handlers.all_detectors_retrieval_handler import AllDetectorsRetrievalHandler 


logging.basicConfig(encoding="utf-8", level=logging.INFO)


class ADOpenSearchHandler(ExtensionRestHandler): 
    def __init__(self): 
        self.routes_map = [
            (re.compile(r"^/detectors$"), RestMethod.GET, AllDetectorsRetrievalHandler.handle_get_all_detectors_request),
            (re.compile(r"^/detectors$"), RestMethod.POST, DetectorCreationHandler.handle_create_detector_request),
            (re.compile(r"^/detectors/(?P<detectorId>[^/]+)$"), RestMethod.GET, DetectorRetrievalHandler.handle_get_detector_request),
            (re.compile(r"^/detectors/(?P<detectorId>[^/]+)$"), RestMethod.PUT, DetectorUpdationHandler.handle_update_detector_request),
            (re.compile(r"^/detectors/(?P<detectorId>[^/]+)$"), RestMethod.DELETE, DetectorDeletionHandler.handle_delete_detector_request),
            (re.compile(r"^/detectors/_detect$"), RestMethod.POST, AnomalyDetectionHandler.handle_detect_anomalies_request),
            (re.compile(r"^/detectors/_preview$"), RestMethod.POST, DetectorPreviewingHandler.handle_preview_detector_request),
        ] 


    def handle_request(self, rest_request: ExtensionRestRequest) -> ExtensionRestResponse:
        logging.debug(f"Handling request: {rest_request.method} {rest_request.path}") 
        method = rest_request.method
        path = rest_request.path 
        for route_pattern, route_method, handler in self.routes_map: 
            match = route_pattern.match(path) 
            if match and method == route_method:
                response = handler(rest_request) 
                return response 
            else:
                logging.warning(f"No handler found for method {method} and path {path}. ")  
                response_bytes = bytes(f"No handler found for method {method} and path {path}. ", "utf-8")
                response = ExtensionRestResponse(rest_request, RestStatus.NOT_FOUND, response_bytes, ExtensionRestResponse.TEXT_CONTENT_TYPE)
        
        return response 

    
    @property
    def routes(self) -> list[NamedRoute]:
        return [
            NamedRoute(method=RestMethod.GET, path="/detectors", unique_name="get_all_detectors"), 
            NamedRoute(method=RestMethod.POST, path="/detectors", unique_name="create_detector"), 
            NamedRoute(method=RestMethod.GET, path="/detectors/{detectorId}", unique_name="get_detector"), 
            NamedRoute(method=RestMethod.PUT, path="/detectors/{detectorId}", unique_name="update_detector"), 
            NamedRoute(method=RestMethod.DELETE, path="/detectors/{detectorId}", unique_name="delete_detector"), 
            NamedRoute(method=RestMethod.POST, path="/detectors/_detect", unique_name="detect_anomalies"), 
            NamedRoute(method=RestMethod.POST, path="/detectors/_preview", unique_name="preview_detector"), 
        ]
 




