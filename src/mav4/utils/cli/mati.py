# Native Imports
from os import environ, path
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
@click.option('--itemtype', type=click.Choice(['indicator', 'actor', 'malware', 'vulnerability', 'reports']), help='Item type to download')
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def download(limit, itemtype, start, end, destdir):
    """
    Download data
    """
    date_format = "%Y-%m-%d"
    start_dt = datetime.strptime(start, date_format)
    end_dt = datetime.strptime(end, date_format)
    # The results JSON contains a slightly different key than the requested item type.
    result_keys = {
        "actor": "threat-actors",
        "indicator": "indicators",
        "malware": "malware",
        "vulnerability": "vulnerability",
        "reports": "objects",
    }

    client = MAV4(username, password)
    items = client.get_items(itemtype, start=start_dt, end=end_dt, limit=limit)
    if destdir:
        logger.debug("Writing to disk %s" % destdir)
        for item in items[result_keys[itemtype]]:
            with open(path.join(destdir, item["id"]+ ".json"), "w") as outfile:
                outfile.write(dumps(item, indent = 4))
    else:
        print(dumps(items))

@mati.command('search')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.argument('query')
def search(limit, query):
    """
    Search the CTI
    """

    client = MAV4(username, password)
    items = client.search(query, limit=limit)
    print(dumps(items))

