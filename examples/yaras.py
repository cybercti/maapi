# Native Imports
from os import environ
import logging
from json import dumps
# 3rd-Party Imports
from maapi.mati import MAV4


logging.basicConfig(filename=None, encoding='utf-8', level=logging.DEBUG)

username = environ['MAV4_USER']
password = environ['MAV4_PASS']
malware_id = "malware--f1151a22-9d9c-589d-90ad-1157ea90033e" # EMOTET

if __name__ == "__main__":
    client = MAV4(username, password)
    yaras = client.get_yara(malware_id=malware_id)
    print(dumps(yaras, indent=4))
    # And get 10(ish) more
    malwares = client.get_items("malware", limit=10)
    for malware in malwares["malware"]:
        if malware["has_yara"]:
            yaras = client.get_yara(malware_id=malware["id"])
            print(dumps(yaras["signatures"], indent=4))

