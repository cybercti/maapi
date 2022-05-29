# Native Imports
from os import environ
import logging
from datetime import datetime
from json import dumps

# 3rd-Party Imports
import click
from mav4.v4client import MAV4


logger = logging.getLogger(__name__)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']


@click.group()
def mati():
    """
    MATI CLI of MAV4
    """


@mati.command('download')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.option('--itemtype', type=click.Choice(['indicator', 'actor', 'malware', 'vulnerability']), help='Item type to download')
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
def download(limit, itemtype, start, end):
    """
    Download data
    """
    date_format = "%Y-%m-%d"
    start_dt = datetime.strptime(start, date_format)
    end_dt = datetime.strptime(end, date_format)

    client = MAV4(username, password)
    items = client.get_items(itemtype, start=start_dt, end=end_dt, limit=limit)
    print(dumps(items))

@mati.command('search')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.option('--query', help="Search query")
def search(limit, query):
    """
    Search the CTI
    """

    client = MAV4(username, password)
    items = client.search(query, limit=limit)
    print(dumps(items))

