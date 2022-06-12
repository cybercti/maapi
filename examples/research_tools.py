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

    resp = client.search_research_tools(query='cats')
    print(f"Found {resp['total_docs']} but limited to {len(resp['docs'])}")

    doc_types = ["paste", "message"]
    resp = client.search_research_tools(query='cats', limit=1, doc_types=doc_types)
    print(f"Found {resp['total_docs']} but limited to {len(resp['docs'])}")

    since = "2022-05-01T00:00:00.000Z"
    until = "2022-05-01T06:00:00.000Z"
    resp = client.search_research_tools(query='cats', limit=1, since=since, until=until)
    print(f"Found {resp['total_docs']} but limited to {len(resp['docs'])}")
    print(dumps(resp, indent=4))
    
    document = resp["docs"][0]
    resp = client.get_document(document["__id"], document["__type"], truncate=40)
    print(dumps(resp, indent=4))

