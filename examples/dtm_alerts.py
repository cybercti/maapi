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

    resp = client.get_monitor_list(limit=1)
    monitor_id = resp['monitors'][0]['id']

    since = "2022-06-01T00:00:00.000Z"
    until = "2022-06-01T01:00:00.000Z"
    resp = client.get_alerts_all(size=5, since=since, until=until, monitor_ids=monitor_id, truncate=40)
    num_alerts = len(resp["alerts"])
    print(f"Found a total of {num_alerts} alerts for Monitor {monitor_id} from {since} to {until}")
    if num_alerts > 0:
        alert_id = resp["alerts"][0]["id"]
        resp = client.get_alert(alert_id=alert_id, truncate=40, sanitize="false")
        print(dumps(resp, indent=4))
    else:
        print("Adjust the date in 'since' and 'until' in order to retrieve alert results.")
