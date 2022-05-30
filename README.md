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

Using the CLI to get data, outputs to stdout:
```
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype indicator
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype malware
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype actor
mati download --limit 5 --start 2022-04-01 --end 2022-04-02 --itemtype vulnerability
```

Download and save entries to disk rather than stdout
``` 
mati download --limit 50 --start 2022-04-01 --end 2022-04-02 --itemtype vulnerability --destdir tmp
```

Seach the data:
```
mati search --limit 5 8.8.8.8
```