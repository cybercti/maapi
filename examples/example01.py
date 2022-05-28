# Native Imports
from os import environ
import logging

# 3rd-Party Imports
from mav4.v4client import MAV4

logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']

if __name__ == "__main__":
    client = MAV4(username, password)
    malware = client.get_items("malware")
    print(malware)
