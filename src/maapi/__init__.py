__all__ = ["mati", "dtm"]

# Standard imports
import logging
from time import time
from os import path
from json import dumps
from ipaddress import ip_address

# Third party imports
from requests import Session
from requests.auth import HTTPBasicAuth

# Local Imports

logger = logging.getLogger(__name__)

class MAAPI(object):
    """
    API client for Mandiant Advantage API
    """

    APP_NAME = "cybercti client"

    def __init__(self, username=None, password=None, token=None, host="https://api.intelligence.fireeye.com"):
        self.username = username
        self.password = password
        self.host = host
        self._session = Session()
        self._request_headers = {
            "accept": "application/json",
            "X-App-Name": MAAPI.APP_NAME,
        }
        if token is None:
            self._auth()
        else:
            self.token = token["token"]
            self._update_auth_struct()
            self.token_expiration_time = token["token_expiration_time"] # But override the expiration.

    def _update_auth_struct(self):
        self.token_expiration_time = time() + self.token["expires_in"]  # Stored as seconds since epoch as a float.
        self.bearer_token = f"Bearer {self.token['access_token']}"
        self._request_headers["Authorization"] = self.bearer_token

    def _auth(self):
        """
        Returns an access token.
        """
        auth = HTTPBasicAuth(self.username, self.password)
        url = f"{self.host}/token"
        data = { "grant_type": "client_credentials" }
        headers = { "content-type": "application/x-www-form-urlencoded" }
        self.token = self._session.post(url=url, data=data, headers=headers, auth=auth).json()
        self._update_auth_struct()
        logger.debug(self.token)


    def _save_auth(self):
        token_file = path.expanduser("~/.mav4_token")
        with open(token_file, "w", encoding="utf-8") as outfile:
            outfile.write(dumps({"token": self.token, "token_expiration_time": self.token_expiration_time}, indent = 4))

    def _http_request(self, func, url, params=None, ** kwargs):
        """
        Validate the Token is still valid, renewing as needed before
        passing on the request to the Python Requests Session.
        """
        # call the endpoint
        token_time_left = self.token_expiration_time - time()
        if token_time_left > 60: # 60 second buffer
            logger.debug("There is still %.2f seconds left in the token", token_time_left)
        else:
            logger.debug("Token expired, renewing Token.")
            self._auth()
            token_time_left = self.token_expiration_time - time()
            logger.debug("Renewed. There is now %.2f seconds left in the token", token_time_left)
        response = func(url, headers=self._request_headers, params=params, ** kwargs)
        return response

    def _http_get(self, * args, ** kwargs):
        return self._http_request(self._session.get, * args, ** kwargs)

    def _http_post(self, * args, ** kwargs):
        return self._http_request(self._session.post, * args, ** kwargs)

    def _retrieve(self, item_type, start=None, end=None, limit=25, value=None, next_pointer=None):
        url = f"{self.host}/v4/{item_type}"
        if next_pointer is not None:
            params = { "next": str(next_pointer) }
        else:
            params = {
                "limit": limit,
            }
            if start: # Supported by vuln, indicators and reports
                params["start_epoch"] = start.strftime('%s')
            if end: # Supported by vuln, indicators and reports
                params["end_epoch"] = end.strftime('%s')
            if value: # Supported by indicator
                params["value"] = value
        response = self._http_get(url=url, params=params)
        return response

    def _determine_type(self, value):
        """
        Attempt to guess the item_type based on value.
        """
        logger.warning("_determine_type is only partially implemented.")
        try:
            value = ip_address(value)
            return "indicator"
        except ValueError:
            pass
        # actor_values = ["unc", "apt", "fin"]
        return "malware"

    def get_items(self, item_type, start=None, end=None, limit=25, value=None, next_pointer=None):
        """
        Get the items with timestamps from start to end, using limit to limit size,
        Optionally filter by item_type.
        Value can be specified if used with value of indicator.
        If next_pointer is specified, get the next page of results from a previous query.
        Note: These results are NOT as detailed as the results would be if queried individually by ID.
          Use get_detail() for more detailed information on an object.
        """
        response = self._retrieve(item_type, start, end, limit, value, next_pointer)
        if response.status_code == 200:
            data = response.json()
        elif response.status_code == 204:
            data = None
        else:
            logger.error("Error Code of %s with message of %s", response.status_code, response.text)
            raise RuntimeError(response.text)
        return data

    def search(self, query, item_type=None, limit=25, next_pointer=None):
        """
        Search and return results, optionally filtering on item_type, using limit to limit results.
        If next_pointer is specified, get the next page of results from a previous query.
        """
        url = f"{self.host}/v4/search"
        data = {
            "limit": limit,
            "search": query,
        }
        if next_pointer:
            data["next"] = str(next_pointer)
        if item_type: # Currently undocumented parameter, filter results by: threat-actor malware vulnerability indicator report
            data["type"] = item_type
        response = self._http_post(url=url, json=data)
        return response.json()

    def get_detail(self, item_type, item_id):
        """
        Get the details of a given item_id of a specifid item_type.
        """
        url = f"{self.host}/v4/{item_type}/{item_id}"
        response = self._http_get(url=url)
        return response.json()

    def id_lookup(self, value, item_type=None, loose_match=False):
        """
        Searches for a given value, returning the id of the first result.
        Note: This is a bit of a hack as it depends on the current behaviour
        of the search, which returns the most relevant (exact match) first.
        """
        if not item_type:
            item_type = self._determine_type(value)
        response = self.search(value, item_type=item_type, limit=1)["objects"]
        if response:
            if response[0]["value"] != value:
                error_message = f"Expected {value} but got {response[0]['value']}"
                if loose_match:
                    logger.warning(error_message)
                else:
                    logger.error(error_message)
                    raise ValueError(error_message)
            return response[0]["id"]
        # No response found.
        error_message = f"No id found for {value} of item_type: {item_type}"
        logger.error(error_message)
        raise ValueError(error_message)
