# Native Import
import logging


# Local Imports
from maapi import MAAPI

logger = logging.getLogger(__name__)

class DTM(MAAPI):
    """
    API client for Mandiant Advantage Digitial Threat Monitoring.
    """

    def __init__(self, *args, **kwargs):
        self.sub_type = 'DTM'
        super().__init__(*args, **kwargs)

    def get_monitor(self, monitor_id):
        """
        Get the details of a given monitor_id.
        """
        url = f"{self.host}/v4/dtm/monitors/{monitor_id}"
        response = self._http_get(url=url)
        return response.json()
