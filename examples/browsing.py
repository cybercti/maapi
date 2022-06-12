# Native Imports
from os import environ
import logging
from json import dumps

# 3rd-Party Imports
from maapi.dtm import DTM

logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)
logger = logging.getLogger(__name__)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = DTM(username, password)


    doc_types = ["forum_post"]
    resp = client.search_research_tools(query='ssh', limit=10, doc_types=doc_types)
    print(f"Found {resp['total_docs']} but limited to {len(resp['docs'])}")
    print(dumps(resp, indent=4))

