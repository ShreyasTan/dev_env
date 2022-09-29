"""This classes are used to collect the mme stats """
#!/bin/python
import json
import sys
import signal
import time
import urllib2

from stats_utility import Utility, ClientStatsSender


COLLECTION_NAME = "MmeStatsResult"
DURATION_KEY = "mmeStatsDuration"
SCRIPT_NAME = "mmestats"

MANAGEMENT_IP = "hostname -I | awk '{print $1}'"
TIME = "date +%s"

def get_stats_info():
    """ This method returns the collection name and fields which are used in
    this stats.

    Return:
        dict: key=collections name,
              val=Fileds the

    """
    fields = ["timeStamp", "mmeSent", "mmeReceived", "TPS"]
    stats_info_dict = {COLLECTION_NAME: fields}
    return stats_info_dict


class MmeStats(object):
    """Class is defined to parse the mme Statistics information."""

    def __init__(self, client):
        """ The MmeStats initilize Utility class object.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        """
        self.client_obj = client
        self.u_obj = Utility()
        self.answerin = None
        self.answerout = None
        self.answer_sent_prev_timestamp = 0
        self.answer_sent_prev_msg = 0
        self.timestamp_start = None
        self.timestamp_end = None
        self.mme_data = None
        self.mme_sent = 0
        self.mme_received = 0
        self.tps = 0
        self.pod_name = None
        self.management_ip = None
        self.mmePort = 0
        

    def execute_mmeStats(self):
        """This method execute all mme stats commands.
        Taking avg of start and end time because execution of all commmands
        takig nearly one second .

        Args:
            self (instance): it refers to the variables and methods of the same
            class.

        Returns:
            None - Nothing is returned

        """
        self.management_ip = Utility.command_executer("{}".format(MANAGEMENT_IP))
        self.mmePort = self.get_mme_port()
        self.timestamp_start = Utility.command_executer("{}".format(TIME))
        self.mme_sent, self.mme_received, self.pod_name = self.fetch_mme_data()
        self.timestamp_end = Utility.command_executer("{}".format(TIME))
        self.tps = self.calculate_tps()

    def get_mme_port(self):
        """This method is used to get the mme port
        count.

        Args:
            None

        Returns:
            port(str): mme port
        """
        return Utility.get_field_value("mmePort")

    def fetch_mme_data(self):
        """This method is used to get the mme data.

        Args:
            None

        Returns:
            None
        """
        try:
            url = "http://{}:{}/get_status".format(self.management_ip, self.mmePort)
            req = urllib2.Request(url)
            response = urllib2.urlopen(req)
            json_response = json.load(response)
            data = json_response["data"]
            return data[0], data[1], data[2]
        except:
            return 0,0,""

    def calculate_tps(self):
        """This Method  returns request out tps
        Returns:
            float: Tps of the mme received.
        """
        interval_msg_count = int(self.mme_received) - int(self.answer_sent_prev_msg)
        interval_duration = self.get_time_stamp() - self.answer_sent_prev_timestamp
        self.answer_sent_prev_timestamp = self.get_time_stamp()
        self.answer_sent_prev_msg = int(self.mme_received)
        if not interval_duration:
            return 0
        tps_count = interval_msg_count/interval_duration
        return round(float(tps_count), 2)

    def get_time_stamp(self):
        """This method returns date and time.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int - date and time

        """
        try:
            return (int(self.timestamp_start)+int(self.timestamp_end))/2
        except ValueError:
            return -1

    def get_mme_sent(self):
        """This method returns mme sent count.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int: mme sent count.

        """
        try:
            return int(self.mme_sent)
        except ValueError:
            return -1

    def get_mme_Received(self):
        """This method returns mme received count.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int: mme received count.

        """
        try:
            return int(self.mme_received)
        except ValueError:
            return -1

    def get_pod_name(self):
        """This method returns pod name.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            str: pod name.

        """
        try:
            return str(self.pod_name)
        except ValueError:
            return ""

    def get_tps(self):
        """This method returns tps.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int: tps.

        """
        try:
            return int(self.tps)
        except ValueError:
            return -1

    def send_mme_stats(self):
        """This method sends the mme stats information to pushgateway and stats collector.

        Args:
           None

        Returns:
            None
        """
	    #Note: Field name should be in [a-zA-Z_:][a-zA-Z0-9_:]* regex pattern
        #Examples: 
        #1. Field which contains with bracket not supported --> "cpu(%)": self.get_cpu()
        #2. Field which starts with number not supported --> 5xxx_ans_sent":  10
        sys_dict = {"timeStamp":self.get_time_stamp(),
                    "mmeSent": self.get_mme_sent(),
                    "mmeReceived": self.get_mme_Received(),
                    "podName": self.get_pod_name(),
                    "TPS": self.get_tps(),
                    "collectionName": COLLECTION_NAME,
                    "otherInfo":{"scriptName": SCRIPT_NAME}
		        }
        self.client_obj.send_stats_to_server(sys_dict)

if __name__ == '__main__':
    DURATION = Utility.get_duration(DURATION_KEY)
    STAT_OBJ = ClientStatsSender()
    SYS_OBJ = MmeStats(STAT_OBJ)
    DONE = True

    def sigint_handler(signum, frame):
        """ This method catch the signal and perform respective action.
        """
        global DONE
        DONE = False

    signal.signal(signal.SIGINT, sigint_handler)

    while DONE:
        START_TIME = time.time()
        SYS_OBJ.execute_mmeStats()
        END_TIME = time.time()
        SYS_OBJ.send_mme_stats()
        time.sleep(DURATION-(END_TIME-START_TIME))
