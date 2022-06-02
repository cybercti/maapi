# mav4
MA V4 API

Unofficial and experimental python client for the Mandiant Advantage platform, starting with the Threat Intelligence endpoints.

# Install
```
git clone https://github.com/cybercti/mav4.git
cd mav4
pip install -r requirements.txt .
```
# Usage
For the python module, the examples and the CLI, make sure to set your API keys as environment variables
```
export MAV4_USER=2122...99
export MAV4_PASS=4991...78
```

# Examples
Check out the examples folder to see basic usage.
```
python mav4/malwares.py
python mav4/actors.py
python mav4/search.py
```

# CLI

There is also a simple CLI to pull data from the Threat Intelligence API. The command is available as *mati*. Usage output and examples are below.

## Usage
```
mati --help
Usage: mati [OPTIONS] COMMAND [ARGS]...

  MATI CLI of MAV4

Options:
  --help  Show this message and exit.

Commands:
  download  Download data
```

The Download command is the first available command
```
mati download --help
Usage: mati download [OPTIONS]

  Download data

Options:
  --limit INTEGER                 Number of items to retrieve
  --itemtype [indicator|actor|malware|vulnerability]
                                  Item type to download
  --start TEXT                    Specify start time in the format 'YYYY-MM-DD'
  --end TEXT                      Specify end time in the format 'YYYY-MM-DD'
  --help                          Show this message and exit.
```

Search command is also available
```
mati search --help
Usage: mati search [OPTIONS]

  Search the CTI

Options:
  --limit INTEGER  Number of items to retrieve
  --query TEXT     Search query
  --help           Show this message and exit.
```

## Examples

Using the CLI to get data, outputs to stdout. The API only supports date ranges for indicators, vulns and reports:
```
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype indicator
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype vulnerability
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype report
mati download --limit 5 --itemtype malware
mati download --limit 5 --itemtype actor
```

Download and save entries to disk rather than stdout
``` 
mati download --limit 50 --start 2022-04-01 --end 2022-04-02 --itemtype vulnerability --destdir tmp
```

Search the data:
```
mati search --limit 5 8.8.8.8
mati search --limit 1 --itemtype indicator 8.8.8.8
```

Object specific modules for more detailed results on a specific item (actor, malware, indicator, vuln, report).
```
mati actor threat-actor--0cba715d-3d77-583d-8a07-ff63e480419e
mati actor threat-actor--0cba715d-3d77-583d-8a07-ff63e480419e --destdir examples/tmp
mati malware malware--51249602-4c6b-56a7-af93-239a770cda76
mati indicator ipv4--d5a34595-ab0d-54c4-8abb-6407d3e25f8e
mati vuln vulnerability--5d71741b-19cd-5f31-859c-f6e4534ab22d
mati report 22-00008562
```

Looking up by ID is limited in usefulness. Indicator lookups can also be done by value.

```
mati indicator 8.8.8.8
mati indicator ddns.org
mati indicator http://39.44.58.183:995
mati indicator 6629090b695dc78e8ae5421ad4d0d25d
```

Use `--loosematch` to allow for non-exact matches, otherwise will throw an exception. The `sha256` needs a loosematch since the type for hash objects are always `md5`.
```
// Returns a result with something that contains xxxx
mati indicator xxxx --loosematch

mati indicator 84b4c0f12c30cc06bf8ba85b148a2c466ede9943919b2fb6232b77f98c3039dd --loosematch
```

But these will throw errors. 
```
mati indicator xxxx
84b4c0f12c30cc06bf8ba85b148a2c466ede9943919b2fb6232b77f98c3039dd
```