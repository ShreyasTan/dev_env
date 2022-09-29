#!/usr/bin/env python3

import sys
import os

ABS_PATH = os.path.abspath(".")
if ABS_PATH not in sys.path:
    sys.path.insert(0, ABS_PATH)

from hss.hss.tcp_server import TcpServer

def run():
    """
    Method to run the REST API app

    Args:
        None
    """
    obj = TcpServer()
    obj.run()

if __name__ == '__main__':
    run()
