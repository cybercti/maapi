# Native Import
import logging


# Local Imports
from maapi import MAAPI

logger = logging.getLogger(__name__)

class DTM(MAAPI):
    """
    API client for Mandiant Advantage Digitial Threat Monitoring.
    """

    APP_NAME = "cybercti client"

    def __init__(self, *args, **kwargs):
        self.subtype = 'DTM'
        self.object_id = 0
        super(DTM, self).__init__(*args, **kwargs)
        # super(*args, **kwargs)

    def get_monitor(self, monitor_id):
        """
        Get the details of a given monitor_id.
        """
        url = f"{self.host}/v4/dtm/monitors/{monitor_id}"
        response = self._http_get(url=url)
        return response.json()
