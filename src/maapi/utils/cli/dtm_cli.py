"""
Mandiant Advantage Threat Intelligence CLI
 - Digital Threat Monitoring
"""

# Native Imports
from os import environ
import logging
from json import dumps

# 3rd-Party Imports
import click
from maapi.dtm import DTM

logger = logging.getLogger(__name__)
username = environ['MAV4_USER']
password = environ['MAV4_PASS']

@click.group()
@click.option('--debug/--no-debug', default=False)
def dtm(debug):
    """
    DTM CLI of MAAPI
    """
    if debug:
        logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)
        logger.debug('Debug is on')
    else:
        logging.basicConfig(filename=None, encoding='utf-8', level=logging.WARNING)


def get_print_monitors(client: DTM, limit: int=50, monitor_id: str = None):
    """
    Get and print a list of monitors
    """
    if monitor_id:
        items = []
        items.append(client.get_monitor(monitor_id))
        print_monitor_list(items)
    else:
        items = client.get_monitor_list(limit)
        print_monitor_list(items['monitors'])

def print_monitor_list(items) -> None:
    """
    Print a list of monitors
    """
    print('┌───────────────────────────────────────────────────────────────┐')
    print('│ Monitor ID          |  Status  |  Name                        │')
    print('└───────────────────────────────────────────────────────────────┘')
    for item in items:
        statuses = ""
        if item['enabled']:
            statuses += "\U00002705"
        else:
            statuses += "\U0000274C"
        if item['email_notify_enabled']:
            statuses += "\U0001F4EC"
        else:
            statuses += "--"
        if item['email_notify_immediate']:
            statuses += "\U0001F3C1"
        else:
            statuses += "--"
        print(f"  {item['id']}   {statuses}     {item['name']}")


@dtm.command('monitor')
@click.argument('command', type=click.Choice(['list', 'activate', 'deactivate', 'delete']))
@click.option('--limit', default=50, help="Number of items to retrieve")
@click.option('--monitorid', help="Monitor ID to change.")
def monitor(command, limit, monitorid):
    """
    Monitor related functionality
    """

    client = DTM(username, password)
    if command == 'list':
        get_print_monitors(client, limit=limit, monitor_id=monitorid)

@dtm.command('rtsearch')
@click.argument('query')
@click.option('--limit', default=50, help="Number of items to retrieve")
@click.option('--doctypes', help="List of document types to filter on, separated by commas.")
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
def rtsearch(query, limit, doctypes, start, end):
    """
    Search Research Tools
    """
    client = DTM(username, password)
    if doctypes:
        doctypes = doctypes.split(',')
    resp = client.search_research_tools(query=query, limit=limit, doc_types=doctypes, since=start, until=end)
    print(dumps(resp, indent=4))
