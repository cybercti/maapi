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

    resp = client.get_monitor_list(limit=1)
    monitor_id = resp['monitors'][0]['id']

    since = "2022-06-01T00:00:00.000Z"
    until = "2022-06-01T01:00:00.000Z"
    resp = client.get_alerts_all(size=5, since=since, until=until, monitor_ids=monitor_id)
    print(resp)
