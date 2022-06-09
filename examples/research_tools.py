# Native Imports
from os import environ
import logging

# 3rd-Party Imports
from maapi.dtm import DTM

logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)
logger = logging.getLogger(__name__)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = DTM(username, password)
    resp = client.search_research_tools(query='cats')
    print(resp)

