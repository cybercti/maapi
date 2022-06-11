"""
Mandiant Advantage Threat Intelligence CLI
 - Digital Threat Monitoring
"""

# Native Imports
from os import environ
import logging
from json import dumps
from xmlrpc.client import boolean

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

def print_monitor_list(client: DTM, limit: int) -> None:
    """
    Get and print a list of monitors
    """
    items = client.get_monitor_list(limit)
    logging.debug(dumps(items, indent=4))
    print('┌───────────────────────────────────────────────────────────────┐')
    print('│ Monitor ID          |  Status  |  Name                        │')
    print('└───────────────────────────────────────────────────────────────┘')
    for item in items['monitors']:
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
def monitor(command, limit):
    """
    Monitor related functionality
    """

    client = DTM(username, password)
    if command == 'list':
        print_monitor_list(client, limit)
