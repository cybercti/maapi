# Native Import
import logging
from typing import Dict

# 3rd-Party Imports
from requests.models import parse_header_links

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

    def get_email_settings(self):
        """
        Get the email settings for the organization.
        """
        url = f"{self.host}/v4/dtm/settings/email"
        response = self._http_get(url=url)
        return response.json()

    def get_vocab_openapi(self):
        """
        Get the Open API spec for this REST API
        """
        headers = {
            "accept": "text/yaml"
        }
        url = f"{self.host}/v4/dtm/vocab/openapi"
        response = self._http_get(url=url, headers=headers)
        return response


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

    def _update_monitor_statuses(self, monitor_id, enabled=None, email_notify_enabled=None, email_notify_immediate=None):
        """
        Update one or more of the Monitor Status Fields
        """
        data = {
            "enabled": enabled,
            "email_notify_enabled": email_notify_enabled,
            "email_notify_immediate": email_notify_immediate,
        }
        url = f"{self.host}/v4/dtm/monitors/{monitor_id}"
        response = self._http_patch(url=url, json=data)
        return response.json()

    def enable_monitor(self, monitor_id):
        """
        Enable a Monitor
        """
        return self._update_monitor_statuses(monitor_id, enabled=True)

    def disable_monitor(self, monitor_id):
        """
        Disable a Monitor
        """
        return self._update_monitor_statuses(monitor_id, enabled=False)

    def get_alerts(self, size:int=25, status:str=None, life:str="10m", order:str="desc", refs:str="false",
                   sort:str="created_at", monitor_ids:str=None, since=None, until=None, truncate=None,
                   alert_type=None, search=None, tags=None, sanitize="true", page=None) -> Dict:
        """
        Get a list of alerts, optionally filtered by monitor_ids.
        """
        url = f"{self.host}/v4/dtm/alerts"
        sort_enum = ["id", "created_at", "updated_at", "monitor_id"]
        if page:
            params = {"page": page}
        else:
            params = {
                "size": size,
                "status": status,
                "life": life,
                "order": order,
                "refs": refs,
                "sort": sort,
                "monitor_id": monitor_ids,
                "since": since,
                "until": until,
                "truncate": truncate,
                "alert_type": alert_type,
                "search": search,
                "tags": tags,
                "sanitize": sanitize,
            }
        response = self._http_get(url=url, params=params)
        if response.headers.get("Link", ""):
            header = response.headers["Link"]
            link_url = parse_header_links(header)[0]["url"] # This is a hack as python requests expects the key to be "links", not "Links"
            page_value = link_url.split("page=")[1] # Grab the value after "page="
            logger.debug("Detected more results are present %s", page_value)
            response = response.json()
            response["_maapi"] = {}
            response["_maapi"]["next_page"] = page_value
            return response
        return response.json()

    def get_alerts_all(self, * args, ** kwargs) -> Dict:
        """
        Get all the alerts for a given query or timeframe.
        """
        alerts = []
        resp = self.get_alerts(* args, ** kwargs)
        alerts += resp["alerts"]
        next_page = resp.get("_maapi", {}).get("next_page", None)
        while next_page:
            resp = self.get_alerts(page=next_page)
            alerts += resp["alerts"]
            next_page = resp.get("_maapi", {}).get("next_page", None)
        return {"alerts": alerts}

    def search_research_tools(self, query, limit=25, doc_types=None, since=None, until=None, truncate=None):
        """
        Search Research Tools
        """
        url = f"{self.host}/v4/dtm/docs/search"
        params = {
            "size": limit,
            "doc_type": doc_types,
            "since": since,
            "until": until,
            "truncate": truncate,
        }
        data = {
            "query": query
        }
        response = self._http_post(url=url, json=data, params=params)
        return response.json()

    def get_document(self, doc_id, doc_type, refs=False, truncate=None, sanitize=True):
        """
        Retrieve document by doc_id and doc_type.
        Options to include the entities and classifiations (refs), optionally truncate the text and sanitize the HTML.
        """
        url = f"{self.host}/v4/dtm/docs/{doc_type}/{doc_id}"
        params = {
            "refs": refs,
            "truncate": truncate,
            "sanitize": sanitize,
        }
        response = self._http_get(url=url, params=params)
        return response.json()

    def get_forum_boards(self, forum_id:int) -> Dict:
        """
        Retrieve a list of Boards for a given forum_id
        """
        url = f"{self.host}/v4/dtm/views/forums/{forum_id}"
        response = self._http_get(url=url)
        return response.json()

    def get_forum_boards_threads(self, forum_id:int, board_name:int) -> Dict:
        """
        Retrieve a list of Threads for a given forum_id and board_name
        """
        url = f"{self.host}/v4/dtm/views/forums/{forum_id}/boards"
        params = {
            "board": board_name
        }
        response = self._http_get(url=url, params=params)
        return response.json()
