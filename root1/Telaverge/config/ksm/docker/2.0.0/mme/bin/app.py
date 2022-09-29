#!/usr/bin/env python3

import sys
import os

ABS_PATH = os.path.abspath(".")
if ABS_PATH not in sys.path:
    sys.path.insert(0, ABS_PATH)

from mme.mme.task_handler import TaskHandler

def run():
    """
    Method to run the REST API app

    Args:
        None
    """
    obj = TaskHandler()

if __name__ == '__main__':
    run()
