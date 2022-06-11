"""
Mandiant Advantage Threat Intelligence CLI
 - Digital Threat Monitoring
"""

# Native Imports
from os import environ, path
import logging
from datetime import datetime
from json import dumps

# 3rd-Party Imports
import click
from maapi.dtm import DTM

logging.basicConfig(filename=None, encoding='utf-8', level=logging.WARNING)

logger = logging.getLogger(__name__)
username = environ['MAV4_USER']
password = environ['MAV4_PASS']

@click.group()
def dtm():
    """
    DTM CLI of MAAPI
    """

@dtm.command('monitor')
@click.argument('command', type=click.Choice(['list', 'activate', 'deactivate', 'delete']))
def monitor(command):
    """
    Monitor related functionality
    """

    client = DTM(username, password)
    if command == 'list':
        items = client.get_monitor_list()
        logging.debug(dumps(items, indent=4))
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
            print(f"{item['id']} {statuses}  {item['name']}")
