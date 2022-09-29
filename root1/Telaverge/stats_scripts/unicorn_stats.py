"""
#Add module string.
"""
#!/bin/python

import sys
import signal
import time
import logging
import datetime
import re
import urllib2
import json
from stats_utility import Utility, ClientStatsSender

COLLECTION_NAME = "UnicornStats"
DURATION_KEY = "UnicornStatsDuration"
SCRIPT_NAME = "unicornstat"


def get_stats_info():
    """ This method returns the collection name and fields which are used in
    this stats.

    Return:
        dict: key=collections name,
              val=Fileds the

    """
    fields = ["timeStamp", "ServerStatsData", "ClientStatsData", "TotalMessagesHandled", "TPS"]
    #Eg: fileds = ["CPU(%)", "Load"]
    stats_info_dict = {COLLECTION_NAME: fields}
    return stats_info_dict

class UnicornStat(object):
    """
    #Add doc string
    """

    def __init__(self, client):
        """ The DatetimeServerStat initilize Utility class object.

        Args:
            client(instance): Object of the ClientStatsSender class.

        """
        self._client_obj = client
        self.time_stamp = None
        self.server_connection_dict = None
        self.client_connection_dict = None
        self.msgandtps_dict = None

    def execute_server_unicornstat(self, dict_):
        """This method excutes stats commands for server

        Args:
            None:

        Returns:
            None - Nothing is returned
        """
        # TODO
        # need to be included if required

    def execute_client_unicornstat(self, dict_):
        """This method excutes stats commands for client

        Args:
            None:

        Returns:
            None - Nothing is returned
        """
        sut = dict_["sutName"]
        ts = dict_["testSuiteName"]
        tc = dict_["testCaseName"]
        client_stats_api = "http://localhost:5000/tests/{}/{}/{}/CLIENT_TEST_STATISTICS".format(
            sut, ts, tc)
        try:
            req = urllib2.Request(client_stats_api)
            response = urllib2.urlopen(req)
            json_response = json.load(response)
            client_stats_1 = json_response["stats"].encode('utf-8').split('\n')
            for stats_1 in client_stats_1:
                client_stats_2 = stats_1.split(";")
                for stats_2 in client_stats_2:
                    if "Messages Sent=" in stats_2:
                        messages_sent = stats_2.split("=")[1]
                    elif "TPS=" in stats_2:
                        total_tps = stats_2.split("=")[1]
            self.client_connection_dict = {
                "TotalMessagesHandled": int(messages_sent.replace(",", "")),
                "TPS": int(total_tps.replace(",", ""))
                }
            self.send_unicorn_client_stat()
        except Exception as exc:
            return False
        return True

    def execute_unicornstat(self, dict_):
        """This method execute stats commands.
        Take avg of start and end time because execution of all commmands
        takig nearly one second .

        Args:
            None:

        Returns:
            None - Nothing is returned

        """
        # TODO
        # currently handles client statistics
        # need to change if required
        sut = dict_["sutName"]
        ts = dict_["testSuiteName"]
        tc = dict_["testCaseName"]
        client_stats_api = "http://localhost:5000/tests/{}/{}/{}/CLIENT_TEST_STATISTICS".format(
            sut, ts, tc)
        try:
            req = urllib2.Request(client_stats_api)
            response = urllib2.urlopen(req)
            json_response = json.load(response)
            client_stats_1 = json_response["stats"].encode('utf-8').split('\n')
            for stats_1 in client_stats_1:
                client_stats_2 = stats_1.split(";")
                for stats_2 in client_stats_2:
                    if "Messages Sent=" in stats_2:
                        messages_sent = stats_2.split("=")[1]
                    elif "TPS=" in stats_2:
                        total_tps = stats_2.split("=")[1]
            self.msgandtps_dict = {
                "TotalMessagesHandled": int(messages_sent.replace(",", "")),
                "TPS": int(total_tps.replace(",", ""))
                }
            self.send_unicorn_stat()
        except Exception as exc:
            return False
        return True

    def send_unicorn_client_stat(self):
        """This method sends the unicorn client stats information to pushgateway
        and stats collector.

        Args:
            None

        Returns:
            None
        """
        #Note: Field name should be in [a-zA-Z_:][a-zA-Z0-9_:]* regex pattern
        #Examples: 
        #1. Field which contains with bracket not supported --> "cpu(%)": self.get_cpu()
        #2. Field which starts with number not supported --> 5xxx_ans_sent":  10

        sys_dict = {
            "timeStamp": self.time_stamp,
            "collectionName": COLLECTION_NAME,
            "otherInfo": {"ScriptName": SCRIPT_NAME}
            }
        sys_dict.update(self.client_connection_dict)
        self._client_obj.send_stats_to_server(sys_dict)

    def send_unicorn_server_stat(self):
        """This method sends the unicorn server stats information to pushgateway
        and stats collector.

        Args:
            None

        Returns:
            None
        """
        #Note: Field name should be in [a-zA-Z_:][a-zA-Z0-9_:]* regex pattern
        #Examples: 
        #1. Field which contains with bracket not supported --> "cpu(%)": self.get_cpu()
        #2. Field which starts with number not supported --> 5xxx_ans_sent":  10
        sys_dict = {
            "timeStamp": self.time_stamp,
            "collectionName": COLLECTION_NAME,
            "otherInfo": {"ScriptName": SCRIPT_NAME}
            }
        sys_dict.update(self.server_connection_dict)
        self._client_obj.send_stats_to_server(sys_dict)

    def send_unicorn_stat(self):
        """This method sends the unicorn stats information to pushgateway
        and stats collector.

        Args:
            None

        Returns:
            None
        """
        #Note: Field name should be in [a-zA-Z_:][a-zA-Z0-9_:]* regex pattern
        #Examples: 
        #1. Field which contains with bracket not supported --> "cpu(%)": self.get_cpu()
        #2. Field which starts with number not supported --> 5xxx_ans_sent":  10

        sys_dict = {
            "timeStamp": self.time_stamp,
            "collectionName": COLLECTION_NAME,
            "otherInfo": {"ScriptName": SCRIPT_NAME}
            }
        sys_dict.update(self.msgandtps_dict)
        self._client_obj.send_stats_to_server(sys_dict)

if __name__ == '__main__':
    CLIENT_OBJ = ClientStatsSender()
    DURATION = Utility.get_duration(DURATION_KEY)
    STATS_OBJ = UnicornStat(CLIENT_OBJ)
    DONE = True

    def sigint_handler(signum, frame):
        """ This method catch the signal and perform respective action.
        """
        global DONE
        DONE = False

    signal.signal(signal.SIGINT, sigint_handler)
    DICT = Utility.get_header_updated_dict()
    single_node = Utility.get_field_value("SingleNode")
    while DONE:
        if single_node:
            STATS_OBJ.execute_unicornstat(DICT)
        else:
            node_type = Utility.get_field_value("NodeType")
            if node_type == "Client":
                STATS_OBJ.execute_client_unicornstat(DICT)
            else:
                STATS_OBJ.execute_server_unicornstat(DICT)
        time.sleep(DURATION)
