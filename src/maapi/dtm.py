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

    def get_monitor_list(self, limit=50):
        """
        Get a list of monitors
        """
        url = f"{self.host}/v4/dtm/monitors"
        params = {
            "size": limit,
        }
        response = self._http_get(url=url, params=params)
        return response.json()

    def get_alerts(self, size=25, status=None, life="10m", order="desc", refs="false", sort="created_at", monitor_ids=None):
        """
        Get a list of monitors, optionally filtered by monitor_ids.
        """
        url = f"{self.host}/v4/dtm/alerts"
        params = {
            "size": size,
            "status": status,
            "life": life,
            "order": order,
            "refs": refs,
            "sort": sort,
            "monitor_id": monitor_ids
        }
        response = self._http_get(url=url, params=params)
        return response.json()

    def search_research_tools(self, query, limit=25, doc_types=None, since=None, until=None):
        """
        Search Research Tools
        """
        url = f"{self.host}/v4/dtm/docs/search"
        params = {
            "size": limit,
            "doc_type": doc_types,
            "since": since,
            "until": until,
        }
        data = {
            "query": query
        }
        response = self._http_post(url=url, json=data, params=params)
        return response.json()
