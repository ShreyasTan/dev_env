#!/usr/bin/env python3

import sys
import os

ABS_PATH = os.path.abspath(".")
if ABS_PATH not in sys.path:
    sys.path.insert(0, ABS_PATH)

from hss.hss.task_handler import TaskHandler

def run():
    """
    Method to run the REST API app

    Args:
        None
    """
    obj = TaskHandler()
    obj.run()

if __name__ == '__main__':
    run()
