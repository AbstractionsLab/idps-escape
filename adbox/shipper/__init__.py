from abc import ABC, abstractmethod

class DataShipper(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def ship_single(self, request, *args):
        pass

    @abstractmethod
    def ship_bulk(self, request, *args):
        pass

    @abstractmethod
    def get_single_request(self, data, *args):
        pass

    @abstractmethod
    def get_bulk_request(self, data, *args):
        pass

    @abstractmethod
    def test_connection(self):
        pass
