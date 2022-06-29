# Native Imports
from os import environ
import logging
from json import dumps
import sys

# 3rd-Party Imports
from maapi.dtm import DTM

logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)
logger = logging.getLogger(__name__)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = DTM(username, password)

    resp = client.get_vocab_openapi()
    print(resp.text)

    resp = client.get_monitor_list(limit=2)
    monitor_id = resp['monitors'][0]['id']
    resp = client.get_monitor(monitor_id)
    print(dumps(resp, indent=4))

    resp = client.get_alerts(1)
    print(dumps(resp))

    resp = client.get_alerts(1, status="read")
    print(dumps(resp))

    resp = client.get_email_settings()
    print(dumps(resp, indent=4))

    print("Skipping some examples as they cause data change, view the source to see the usage.")
    sys.exit(0)
    resp = client.disable_monitor(monitor_id)
    resp = client.enable_monitor(monitor_id)
