__all__ = ["mati", "dtm"]

# Standard imports
import logging
from time import time
from os import path
from json import dumps

# Third party imports
from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

# Local Imports

logger = logging.getLogger(__name__)

class MAAPI(object):
    """
    API client for Mandiant Advantage API
    """

    APP_NAME = "MAAPI client github.com/cybercti/maapi"

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
        response = self._session.post(url=url, data=data, headers=headers, auth=auth)
        # Check the response before returning. TODO: Likely should be included as a part of a larger Exception set maintained in this module.
        try:
            response.raise_for_status()
        except HTTPError as error:
            logger.error('HTTP code of %i : Error in request (%s): %s', response.status_code, error, response.text)
            raise
        self.token = response.json()
        self._update_auth_struct()
        logger.debug(self.token)

    def _save_auth(self):
        token_file = path.expanduser("~/.mav4_token")
        with open(token_file, "w", encoding="utf-8") as outfile:
            outfile.write(dumps({"token": self.token, "token_expiration_time": self.token_expiration_time}, indent = 4))

    def _http_request(self, func, url, headers=None, ** kwargs):
        """
        Validate the Token is still valid, renewing as needed before
        passing on the request to the Python Requests Session.
        """
        # call the endpoint
        token_time_left = self.token_expiration_time - time()
        if token_time_left > 60: # 60 second buffer
            logger.debug("There is still %.2f seconds left in the token", token_time_left)
        else:
            logger.info("Token expired, renewing Token.")
            self._auth()
            token_time_left = self.token_expiration_time - time()
            logger.info("Token Renewed. There is now %.2f seconds left in the token", token_time_left)
        if headers: # Support alternate headers, as some endpoints return text/yaml rather than JSON.
            headers["Authorization"] = self._request_headers["Authorization"]
            response = func(url, headers=headers, ** kwargs)
        else:
            response = func(url, headers=self._request_headers, ** kwargs)

        # Check the response before returning.
        try:
            response.raise_for_status()
        except HTTPError as error:
            logger.error('HTTP code of %i : Error in request (%s): %s', response.status_code, error, response.text)
            raise # TODO: Determine if this should be raised, there might be legitimate non-200 codes that we need to pass on.
        return response

    def _http_get(self, * args, ** kwargs) -> Response:
        return self._http_request(self._session.get, * args, ** kwargs)

    def _http_post(self, * args, ** kwargs) -> Response:
        return self._http_request(self._session.post, * args, ** kwargs)

    def _http_patch(self, * args, ** kwargs) -> Response:
        return self._http_request(self._session.patch, * args, ** kwargs)
