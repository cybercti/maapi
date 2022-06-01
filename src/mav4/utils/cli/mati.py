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
@click.option('--itemtype', type=click.Choice(['indicator', 'actor', 'malware', 'vulnerability', 'report']), help='Item type to download')
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def download(limit, itemtype, start, end, destdir):
    """
    Download data
    """
    date_format = "%Y-%m-%d"
    if start:
        start = datetime.strptime(start, date_format)
    if end:
        end = datetime.strptime(end, date_format)
    # The results JSON contains a slightly different key than the requested item type.
    result_keys = {
        "actor": "threat-actors",
        "indicator": "indicators",
        "malware": "malware",
        "vulnerability": "vulnerability",
        "report": "objects",
    }

    client = MAV4(username, password)
    items = client.get_items(itemtype, start=start, end=end, limit=limit)
    if destdir:
        logger.debug("Writing to disk %s" % destdir)
        for item in items[result_keys[itemtype]]:
            with open(path.join(destdir, item["id"]+ ".json"), "w") as outfile:
                outfile.write(dumps(item, indent = 4))
    else:
        print(dumps(items))

@mati.command('search')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.option('--itemtype', default="all", type=click.Choice(['indicator', 'actor', 'malware', 'vulnerability', 'report']), help='Item type to download')
@click.argument('query')
def search(limit, itemtype, query):
    """
    Search the CTI
    """
    # Keeping the CLI consistent, but the item_type in search is NOT consistent with the other type-specific endpoints.
    # all threat-actor malware vulnerability indicator report
    search_item_type = {
        "actor": "threat-actor",
        "indicator": "indicator",
        "malware": "malware",
        "vulnerability": "vulnerability",
        "report": "report",
        "all": "all",
    }

    client = MAV4(username, password)
    items = client.search(query, item_type=search_item_type[itemtype], limit=limit)
    print(dumps(items))

@mati.command('actor')
@click.argument('actor')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def search(actor, destdir):
    """
    Operations related to Actors
    """

    client = MAV4(username, password)
    response = client.get_detail("actor", actor)
    if destdir:
        with open(path.join(destdir, actor + "-detailed.json"), "w") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('malware')
@click.argument('malware')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def search(malware, destdir):
    """
    Operations related to Malware
    """

    client = MAV4(username, password)
    response = client.get_detail("malware", malware)
    if destdir:
        with open(path.join(destdir, malware + "-detailed.json"), "w") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('vuln')
@click.argument('vuln')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def search(vuln, destdir):
    """
    Operations related to Malware
    """

    client = MAV4(username, password)
    response = client.get_detail("vulnerability", vuln)
    if destdir:
        with open(path.join(destdir, vuln + "-detailed.json"), "w") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('indicator')
@click.argument('indicator')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
def search(indicator, destdir):
    """
    Operations related to an Indicator
    """

    client = MAV4(username, password)
    response = client.get_detail("indicator", indicator)
    if destdir:
        with open(path.join(destdir, indicator + "-detailed.json"), "w") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))
