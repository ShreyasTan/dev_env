import sys
from commands import getoutput
import os

try:
    os.remove("{{ file_name_2 }}")
except Exception:
    pass
command = "tcpdump -i {{ interface_name_2 }} -w {{ file_name_2 }}"
try:
    getoutput(command)
except KeyboardInterrupt as ex:
    sys.exit(1)