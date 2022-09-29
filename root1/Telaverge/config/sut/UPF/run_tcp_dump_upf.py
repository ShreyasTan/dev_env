import sys
from commands import getoutput
import os

try:
    os.remove("{{ file_name_1 }}")
except Exception:
    pass
command = "tcpdump -i {{ interface_name_1 }} -w {{ file_name_1 }}"
try:
    getoutput(command)
except KeyboardInterrupt as ex:
    sys.exit(1)