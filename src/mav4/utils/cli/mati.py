"""
Mandiant Advantage Threat Intelligence CLI
"""

# Native Imports
from os import environ, path
import logging
from datetime import datetime
from json import dumps

# 3rd-Party Imports
import click
from mav4.v4client import MAV4

logging.basicConfig(filename=None, encoding='utf-8', level=logging.WARNING)

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
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True,
              writable=True, resolve_path=True), help="If specified, output is written to disk, one result per file.")
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
        logger.debug("Writing to disk %s", destdir)
        for item in items[result_keys[itemtype]]:
            with open(path.join(destdir, item["id"]+ ".json"), "w", encoding="utf-8") as outfile:
                outfile.write(dumps(item, indent = 4))
        next_pointer = items.get("next", "")
        while next:
            logger.debug("Writing to disk %s with %s", destdir, next_pointer)
            items = client.get_items(itemtype, limit=limit, next_pointer=next_pointer)
            for item in items[result_keys[itemtype]]:
                with open(path.join(destdir, item["id"]+ ".json"), "w", encoding="utf-8") as outfile:
                    outfile.write(dumps(item, indent = 4))
            next_pointer = items.get("next", "")
    else:
        print(dumps(items))

@mati.command('search')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.option('--itemtype', default="all", type=click.Choice(['indicator', 'actor', 'malware', 'vulnerability', 'report']),
              help='Item type to download')
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
@click.argument('name')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True),
              help="If specified, output is written to disk, one result per file.")
def actor(name, destdir):
    """
    Operations related to Actors
    """

    client = MAV4(username, password)
    response = client.get_detail("actor", name)
    if destdir:
        name = response["id"] # Input can be APT, FIN, UNC or MA ID, Write to disk using the id
        with open(path.join(destdir, name + "-detailed.json"), "w", encoding="utf-8") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('malware')
@click.argument('name')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True),
              help="If specified, output is written to disk, one result per file.")
def malware(name, destdir):
    """
    Operations related to Malware
    """

    client = MAV4(username, password)
    response = client.get_detail("malware", name)
    if destdir:
        name = response["id"] # Input can be Malware name or MA ID, Write to disk using the id.
        with open(path.join(destdir, name + "-detailed.json"), "w", encoding="utf-8") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('vuln')
@click.argument('name')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True),
              help="If specified, output is written to disk, one result per file.")
def vuln(name, destdir):
    """
    Operations related to Vulnerabilties
    """

    client = MAV4(username, password)
    response = client.get_detail("vulnerability", name)
    if destdir:
        name = response["id"] # Input can be CVE or MA ID, Write to disk using the id
        with open(path.join(destdir, name + "-detailed.json"), "w", encoding="utf-8") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('indicator')
@click.argument('name')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True),
              help="If specified, output is written to disk, one result per file.")
@click.option('--loosematch', '-l', is_flag=True, help="Return result even if not an exact match.")
def indicator(name, destdir, loosematch):
    """
    Operations related to an Indicator
    """
    client = MAV4(username, password)

    prefixes = ["md5--", "ipv4--", "fqdn--", "url--"]
    lookup_needed = True
    for prefix in prefixes:
        if prefix in name:
            lookup_needed = False
            break
    if lookup_needed:
        name = client.id_lookup(name, "indicator", loose_match=loosematch)

    response = client.get_detail("indicator", name)
    if destdir:
        with open(path.join(destdir, indicator + "-detailed.json"), "w", encoding="utf-8") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))

@mati.command('report')
@click.argument('name')
@click.option('--destdir', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, resolve_path=True),
              help="If specified, output is written to disk, one result per file.")
def report(name, destdir):
    """
    Operations related to Reports
    """

    client = MAV4(username, password)
    response = client.get_detail("report", name)
    if destdir:
        with open(path.join(destdir, name + "-detailed.json"), "w", encoding="utf-8") as outfile:
            outfile.write(dumps(response, indent = 4))
    else:
        print(dumps(response, indent=4))
