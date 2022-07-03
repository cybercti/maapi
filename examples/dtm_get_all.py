# Native Imports
from os import environ
import logging

# 3rd-Party Imports
from maapi.dtm import DTM

logging.basicConfig(filename=None, encoding='utf-8', level=logging.WARN)
logger = logging.getLogger(__name__)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = DTM(username, password)

    resp = client.get_monitor_all()
    num_results = len(resp["monitors"])
    print(f"Found and retrieved a total of {num_results} monitors")

    monitor_id = resp['monitors'][0]['id']
    since = "2022-06-01T00:00:00.000Z"
    until = "2022-06-01T01:00:00.000Z"
    resp = client.get_alerts_all(size=5, since=since, until=until, monitor_ids=monitor_id)
    num_results = len(resp["alerts"])
    print(f"Found and retrieved a total of {num_results} alerts for Monitor {monitor_id} from {since} to {until}")

    query = "hack"
    since = "2022-05-01T00:00:00.000Z"
    until = "2022-05-02T15:40:00.000Z"
    resp = client.search_research_tools_all(query=query, since=since, until=until)
    num_results = len(resp["docs"])
    print(f"Found and retrieved a total of {num_results} documents for our Search '{query}' from {since} to {until}")
