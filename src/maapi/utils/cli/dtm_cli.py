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

# Local Imports
from .dtm_renderings import _render_preview
from .dtm_tsv_renderings import render_tsv_entry_shop_listing_cc, render_tsv_entry_shop_listing_cc_header

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


def get_print_monitors(client: DTM, limit: int=0, monitor_id: str = None):
    """
    Get and print a list of monitors
    """
    if monitor_id:
        items = []
        items.append(client.get_monitor(monitor_id))
    else:
        if limit > 0:
            items = client.get_monitor_list(limit)['monitors']
        else:
            items = client.get_monitor_all()['monitors']
    print_monitor_list(items)

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


def retrieve_bins_from_file(filename:str) -> str:
    """
    Retrieve a list of BINs from a file and returns a comma delimited version of them.
    """
    with open(filename, "r", encoding="utf-8") as bin_file:
        bin_list = bin_file.read().replace('\n', ',')
        while bin_list[-1:] == ',': # Remove any trailing commas/new-lines
            bin_list = bin_list[:-1]
    return bin_list


@dtm.command('monitor')
@click.argument('command', type=click.Choice(['list', 'enable', 'disable']))
@click.option('--limit', default=0, help="Number of items to retrieve, 0 for unlimited.")
@click.option('--monitorid', help="Monitor ID to change.")
def monitor(command, limit, monitorid):
    """
    Monitor related functionality
    """

    client = DTM(username, password)
    if command == 'list':
        get_print_monitors(client, limit=limit, monitor_id=monitorid)
    elif command == 'enable':
        if monitorid:
            client.enable_monitor(monitor_id=monitorid)
            get_print_monitors(client, limit=1, monitor_id=monitorid)
        else:
            print("--monitorid required when enabling or disabling a monitor")
    elif command == 'disable':
        if monitorid:
            client.disable_monitor(monitor_id=monitorid)
            get_print_monitors(client, limit=1, monitor_id=monitorid)
        else:
            print("--monitorid required when enabling or disabling a monitor")

@dtm.command('rtsearch')
@click.argument('query')
@click.option('--limit', default=25, help="Number of items to retrieve")
@click.option('--doctypes', help="List of document types to filter on, separated by commas.")
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--truncate', default=None, help="Integer: Limit the response 'body' to a given length.")
@click.option('--output', default="preview", type=click.Choice(['preview', 'json']), help="Specify Output format")
def rtsearch(query, limit, doctypes, start, end, truncate, output):
    """
    Search Research Tools
    """
    client = DTM(username, password)
    if doctypes:
        doctypes = doctypes.split(',')
    resp = client.search_research_tools(query=query, limit=limit, doc_types=doctypes, since=start, until=end, truncate=truncate)
    if output == "preview":
        print('┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐')
        print('│ Type                |  Summary                                                                                             │')
        print('└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘')
        for document in resp["docs"]:
            print(f'  {document["__type"][:20]:20}   ', end='')
            print(_render_preview(document))
    elif output == "json":
        print(dumps(resp, indent=4))

@dtm.command('cards')
@click.argument('bin_list') # , help="List of BINs to filter on, separated by commas."
@click.option('--start', help="Specify start time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--end', help="Specify end time in the format 'YYYY-MM-DDTH:M:SZ'")
@click.option('--output', default="tsv", type=click.Choice(['tsv', 'json', 'jsonl']), help="Specify Output format")
@click.option("--usefile", is_flag=True, show_default=True, default=False,
    help="If enabled, bin_list is considered a file in which to read, one line per BIN.")
@click.option('--pagecount', default=1, help="Number of pages to retrieve, use 0 to retrieve all.")
def bins(bin_list, start, end, output, usefile, pagecount):
    """
    Retrieve a dump of all shop listings cards associated with a comma-delimited list of BINs
    """
    client = DTM(username, password)
    doctypes = ["shop_listing"]
    if usefile:
        bin_list = retrieve_bins_from_file(bin_list)
    query = f'item_type:CC AND payment_card.partial_number_prefix:({bin_list.replace(",", " OR ")})'
    results_gen = client.search_research_tools_iter(page_count=pagecount, query=query, doc_types=doctypes, since=start, until=end, truncate=None)
    if output == "tsv":
        print(render_tsv_entry_shop_listing_cc_header())
        for documents in results_gen:
            for document in documents: # Results are in batches
                print(render_tsv_entry_shop_listing_cc(document))
    elif output == "jsonl":
        for documents in results_gen:
            for document in documents: # Results are in batches
                print(dumps(document))
    elif output == "json":
        results = []
        for documents in results_gen:
            results += documents
        print(dumps({"docs": results}, indent=4))
