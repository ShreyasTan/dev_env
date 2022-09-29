#!/usr/bin/env python3

import sys
import os

ABS_PATH = os.path.abspath(".")
if ABS_PATH not in sys.path:
    sys.path.insert(0, ABS_PATH)

from load_balancer.load_balancer.load_balancer import LoadBalancer

def run():
    """
    Method to run the REST API app

    Args:
        None
    """
    obj = LoadBalancer()
    obj.start()

if __name__ == '__main__':
    run()
