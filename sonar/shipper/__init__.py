"""
SONAR Data Shipper - Ship anomaly detection results to Wazuh Indexer.

This module provides functionality to create data streams in Wazuh (OpenSearch)
and ship anomaly detection results for real-time monitoring and alerting.
"""

from abc import ABC, abstractmethod


class DataShipper(ABC):
    """Abstract base class for data shipping implementations."""

    def __init__(self, config):
        """
        Initialize data shipper.

        Args:
            config: Configuration dictionary for the shipper.
        """
        self.config = config

    @abstractmethod
    def ship_single(self, stream_name: str, document: dict):
        """
        Ship a single document to the data stream.

        Args:
            stream_name: Name of the target data stream.
            document: Document to ship.
        """
        pass

    @abstractmethod
    def ship_bulk(self, request):
        """
        Ship multiple documents in bulk.

        Args:
            request: Bulk request body.
        """
        pass

    @abstractmethod
    def get_single_request(self, data: dict, stream_name: str):
        """
        Build a single document request.

        Args:
            data: Document data.
            stream_name: Target stream name.
        """
        pass

    @abstractmethod
    def get_bulk_request(self, data, stream_name: str, actions: list):
        """
        Build a bulk request.

        Args:
            data: List of documents.
            stream_name: Target stream name.
            actions: List of actions (index, create, etc.).
        """
        pass

    @abstractmethod
    def test_connection(self):
        """Test connection to the data store."""
        pass
