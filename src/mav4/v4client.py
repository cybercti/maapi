# Native Import
from ipaddress import ip_address
from time import time
import logging
from os import path
from json import dumps

# Third party imports
from requests import Session
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

class MAV4:

    APP_NAME = "cybercti client"

    def __init__(self, username=None, password=None, token=None, host="https://api.intelligence.fireeye.com"):
        self.username = username
        self.password = password
        self.host = host
        self._session = Session()
        self._request_headers = {
            "accept": "application/json",
            "X-App-Name": MAV4.APP_NAME,
        }
        if token is None:
            self._auth()
        else:
            self.token = token["token"]
            self._update_auth_struct()
            self.token_expiration_time = token["token_expiration_time"] # But override the expiration.

    def _update_auth_struct(self):
        self.token_expiration_time = time() + self.token["expires_in"]  # Stored as seconds since epoch as a float.
        self.bearer_token = "Bearer %s" % self.token["access_token"]
        self._request_headers["Authorization"] = self.bearer_token

    def _auth(self):
        """
        Returns an access token.
        """
        auth = HTTPBasicAuth(self.username, self.password)
        url = "%s/token" % self.host
        data = { "grant_type": "client_credentials" }
        headers = { "content-type": "application/x-www-form-urlencoded" }
        self.token = self._session.post(url=url, data=data, headers=headers, auth=auth).json()
        self._update_auth_struct()
        logger.debug(self.token)


    def _save_auth(self):
        token_file = path.expanduser("~/.mav4_token")
        with open(token_file, "w") as outfile:
            outfile.write(dumps({"token": self.token, "token_expiration_time": self.token_expiration_time}, indent = 4))

    def _http_request(self, func, url, params=None, ** kwargs):
        # call the endpoint
        token_time_left = self.token_expiration_time - time()
        if token_time_left > 60: # 60 second buffer
            logger.debug("There is still %.2f seconds left in the token" % token_time_left)
        else:
            logger.debug("Token expired, renewing Token.")
            self._auth()
            token_time_left = self.token_expiration_time - time()
            logger.debug("Renewed. There is now %.2f seconds left in the token" % token_time_left)
        response = func(url, headers=self._request_headers, params=params, ** kwargs)
        return response

    def _http_get(self, * args, ** kwargs):
        return self._http_request(self._session.get, * args, ** kwargs)

    def _http_post(self, * args, ** kwargs):
        return self._http_request(self._session.post, * args, ** kwargs)

    def _retrieve(self, item_type, start=None, end=None, limit=25, value=None, next_pointer=None):
        url = "%s/v4/%s" % (self.host, item_type)
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
        logger.warning("_determine_type is only partially implemented.")
        try:
            value = ip_address(value)
            return "indicator"
        except ValueError:
            pass
        actor_values = ["unc", "apt", "fin"]
        return "malware"

    def get_items(self, item_type, start=None, end=None, limit=25, value=None, next_pointer=None):
        response = self._retrieve(item_type, start, end, limit, value, next_pointer)
        if response.status_code == 200:
            data = response.json()
        elif response.status_code == 204:
            data = None
        else:
            logger.error("Error Code of %s with message of %s " % (response.status_code, response.text))
            raise RuntimeError(response.text)
        return data

    def search(self, query, item_type=None, limit=25, next_pointer=None):
        url = "%s/v4/search" % (self.host)
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

    def get_detail(self, item_type, id):
        url = "%s/v4/%s/%s" % (self.host, item_type, id)
        response = self._http_get(url=url)
        return response.json()

    def id_lookup(self, value, item_type=None, loose_match=False):
        if not item_type:
            item_type = self._determine_type(value)
        response = self.search(value, item_type=item_type, limit=1)["objects"]
        if response:
            if response[0]["value"] != value: # TODO: Document this hack somewhere. Currently, the first result is usually the most exact/relevant match.
                error_message = "Expected %s but got %s" % (value, response[0]["value"])
                if loose_match:
                    logger.warning(error_message)
                else:
                    logger.error(error_message)
                    raise ValueError(error_message)        
            return response[0]["id"]
        else:
            error_message = "No id found for %s of item_type:  %s" % (value, item_type)
            logger.error(error_message)
            raise ValueError(error_message)
