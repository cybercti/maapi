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
    resp = client.get_monitor_list(size=2)
    monitor_id = resp['monitors'][0]['id']
    resp = client.get_monitor(monitor_id)
    print(resp)
    resp = client.get_alerts(1)
    print(resp)
    resp = client.get_alerts(1, status="read")
    print(resp)
