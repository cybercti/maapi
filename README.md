# MA API v4 Client
MA API

Unofficial and experimental python client for the Mandiant Advantage platform, starting with the Threat Intelligence endpoints.

# Install
```
pip install git+https://github.com/cybercti/maapi.git
```

Or use the older setuptools method. **Warning: Deprecated**
```
git clone https://github.com/cybercti/maapi.git
cd maapi
python setup.py install
```

## Install - Development envirornment
Use `-e` to install project in `editable` mode for local development (i.e. setuptools "develop mode")
```
git clone https://github.com/cybercti/maapi.git
cd maapi
pip install -e .
```

# Usage
For the python module, the examples and the CLI, make sure to set your API keys as environment variables
```
export MAV4_USER=2122...99
export MAV4_PASS=4991...78
```

# Examples
Check out the examples folder to see basic usage.

## MATI related examples
```
python examples/malwares.py
python examples/actors.py
python examples/search.py
```

## DTM related examples
```
python examples/dtm.py
python examples/research_tools.py
```

# CLI

There is also a simple CLI to pull data from the Threat Intelligence API. The command is available as *mati*. Usage output and examples are below.

## MATI Usage
```
Usage: mati [OPTIONS] COMMAND [ARGS]...

  MATI CLI of MAV4

Options:
  --debug / --no-debug
  --help                Show this message and exit.

Commands:
  actor      Operations related to Actors
  download   Download data
  indicator  Operations related to an Indicator
  malware    Operations related to Malware
  report     Operations related to Reports
  search     Search the CTI
  vuln       Operations related to Vulnerabilties
```

The Download command is the first available command
```
Usage: mati download [OPTIONS]

  Download data

Options:
  --limit INTEGER                 Number of items to retrieve
  --itemtype [indicator|actor|malware|vulnerability|report]
                                  Item type to download
  --start TEXT                    Specify start time in the format 'YYYY-MM-
                                  DDTH:M:SZ'
  --end TEXT                      Specify end time in the format 'YYYY-MM-
                                  DDTH:M:SZ'
  --destdir DIRECTORY             If specified, output is written to disk, one
                                  result per file.
  --help                          Show this message and exit.
```

Search command is also available
```
Usage: mati search [OPTIONS] QUERY

  Search the CTI

Options:
  --limit INTEGER                 Number of items to retrieve
  --itemtype [all|indicator|actor|malware|vulnerability|report]
                                  Item type to download
  --help                          Show this message and exit.
```

### Examples

Using the CLI to get data, outputs to stdout. The API only supports date ranges for indicators, vulns and reports. By default, outputs to stdout but only the first page of data.
```
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype indicator
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype vulnerability
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype report
mati download --limit 5 --itemtype malware
mati download --limit 5 --itemtype actor
```

Download and save entries to disk rather than stdout. Saving to disk will paginate and save all of the entries between the date ranges.
``` 
mati download --limit 50 --start 2022-04-01 --end 2022-04-02 --itemtype indicator --destdir tmp
```

Search the data:
```
mati search --limit 5 8.8.8.8
mati search --limit 1 --itemtype indicator 8.8.8.8
```

#### Lookups on single items

Object specific modules for more detailed results on a specific item (actor, malware, indicator, vuln, report).
```
mati actor threat-actor--0cba715d-3d77-583d-8a07-ff63e480419e
mati actor threat-actor--0cba715d-3d77-583d-8a07-ff63e480419e --destdir examples/tmp
mati malware malware--51249602-4c6b-56a7-af93-239a770cda76
mati indicator ipv4--d5a34595-ab0d-54c4-8abb-6407d3e25f8e
mati vuln vulnerability--5d71741b-19cd-5f31-859c-f6e4534ab22d
mati report 22-00008562
```

Looking up by ID is limited in usefulness. Lookups can also be done by value.

```
mati indicator 8.8.8.8
mati indicator ddns.org
mati indicator http://39.44.58.183:995
mati indicator 6629090b695dc78e8ae5421ad4d0d25d
mati vuln CVE-2022-1052
mati actor APT26
mati actor UNC1149
mati malware THREEDOG
```

#### Indicator specific lookup options.
Use `--loosematch` to allow for non-exact matches, otherwise will throw an exception. The `sha256` needs a loosematch since the type for hash objects are always `md5`.
```
// Returns a result with something that contains xxxx
mati indicator xxxx --loosematch
mati indicator 84b4c0f12c30cc06bf8ba85b148a2c466ede9943919b2fb6232b77f98c3039dd --loosematch
```

But these will throw errors. 
```
mati indicator xxxx
mati indicator 84b4c0f12c30cc06bf8ba85b148a2c466ede9943919b2fb6232b77f98c3039dd
```

## DTM Usage

```
Usage: dtm monitor [OPTIONS] {list|enable|disable}

  Monitor related functionality

Options:
  --limit INTEGER   Number of items to retrieve, 0 for unlimited.
  --monitorid TEXT  Monitor ID to change.
  --help            Show this message and exit.
```

```
Usage: dtm rtsearch [OPTIONS] QUERY

  Search Research Tools

Options:
  --limit INTEGER          Number of items to retrieve
  --doctypes TEXT          List of document types to filter on, separated by
                           commas.
  --start TEXT             Specify start time in the format 'YYYY-MM-
                           DDTH:M:SZ'
  --end TEXT               Specify end time in the format 'YYYY-MM-DDTH:M:SZ'
  --truncate TEXT          Integer: Limit the response 'body' to a given
                           length.
  --output [preview|json]  Specify Output format
  --help                   Show this message and exit.
```

```
Usage: dtm cards [OPTIONS] BIN_LIST

  Retrieve a dump of all shop listings cards associated with a comma-delimited
  list of BINs

Options:
  --start TEXT               Specify start time in the format 'YYYY-MM-
                             DDTH:M:SZ'
  --end TEXT                 Specify end time in the format 'YYYY-MM-
                             DDTH:M:SZ'
  --output [tsv|json|jsonl]  Specify Output format
  --usefile                  If enabled, bin_list is considered a file in
                             which to read, one line per BIN.
  --exactmatch               If enabled, bin_list will match exactly on the
                             BIN instead of a prefix, BIN*.
  --pagecount INTEGER        Number of pages to retrieve, use 0 to retrieve
                             all.
  --help                     Show this message and exit.
```

### Examples

#### Monitor related examples:

Get a list of the monitors with corresponding statuses for each.
```
dtm monitor list
dtm monitor list --limit 2
```

Enable or disable a monitor
```
dtm monitor enable  --monitorid a9a9a9a9a9a9a9a9a9a9
dtm monitor disable --monitorid a9a9a9a9a9a9a9a9a9a9
```

#### Research Tools Search examples

```
dtm rtsearch ssh
dtm rtsearch ssh --limit 1 --doctypes forum_post,message,shop_listing,paste,web_content_publish
dtm rtsearch ssh --limit 1 --start 2022-06-01T00:00:00Z --end 2022-06-02T00:00:00Z
```

Specify Different output options, default is `preview` view.
```
dtm rtsearch ssh --limit 10 --doctypes message,paste --truncate 50 --output preview
dtm rtsearch ssh --limit 10 --doctypes message,paste --truncate 50 --output json
```

#### Research Tools shop listing - payment cards downloads

```
dtm cards 372652,440348 --pagecount 1 --output tsv --start 2022-06-01T00:00:00Z --end 2022-06-02T00:00:00Z
```

Get all the cards in the time slot
```
dtm cards 372652,440348 --pagecount 0 --output tsv --start 2022-06-01T00:00:00Z --end 2022-06-02T00:00:00Z
```

Load the BINs from a text file rather than passing on the command line.
```
dtm cards --pagecount 1 --output tsv --start 2023-01-01T00:00:00Z --end 2023-01-15T00:00:00Z --usefile ~/Downloads/mybins.txt
```
