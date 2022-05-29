# Native Imports
from os import environ
import logging
from json import dumps

# 3rd-Party Imports
from mav4.v4client import MAV4


logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = MAV4(username, password)
    response = client.search("8.8.8.8", limit=5)
    print(dumps(response, indent=4))
