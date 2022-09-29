"""This classes are used to collect the mme hss system stats """
#!/bin/python
import sys
import signal
import time

from stats_utility import Utility, ClientStatsSender

COLLECTION_NAME = "MmeHssSysStatsResult"
DURATION_KEY = "mmeHssSysStatsDuration"
SCRIPT_NAME = "mmehsssysstats"
DATE = "date +%s"
CPU_CORE = "nproc"

def get_stats_info():
    """ This method returns the collection name and fields which are used in
    this stats.

    Return:
        dict: key=collections name,
              val=Fileds the

    """
    fields = ["timeStamp", "CPU", "RSS", "VSZ"]
    stats_info_dict = {COLLECTION_NAME: fields}
    return stats_info_dict


class MmeHssSysStats(object):
    """Class is defined to parse the mme hss system Statistics information."""

    def __init__(self, client):
        """ The MmeHssSysStats initilize Utility class object.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        """
        self._client_obj = client
        self.u_obj = Utility()
        self._start_time = None
        self._end_time = None
        self._rss = None
        self._cpu = None
        self._vsz = None

    def execute_mmeHssSysStats(self):
        """This method execute all mme hss system stats commands.
        Taking avg of start and end time because execution of all commmands
        takig nearly one second .

        Args:
            self (instance): it refers to the variables and methods of the same
            class.

        Returns:
            None - Nothing is returned

        """
        self.application_name = Utility.get_field_value("applicationName")
        self.pids = 'ps -elf | grep {} | grep -v grep | tr -s " " | cut -d " " -f 4'.format(self.application_name)
        self._start_time = Utility.command_executer("{}".format(DATE))
        self.process_ids = Utility.command_executer("{}".format(self.pids)).split('\n')
        self._cpu = self.get_cpu_for_pids()
        self._rss = self.get_rss_for_pids()
        self._vsz = self.get_vsz_for_pids()
        self._end_time = Utility.command_executer("{}".format(DATE))

    def get_cpu_for_pids(self):
        """This method returns the total cpu usage for the process id.

        Returns:
            float: total_cpu_usage

        """
        total_cpu_usage = 0
        for process_id in self.process_ids:
            CPU = "ps -p {} -o %cpu=".format(process_id)
            cpu_usage = float(Utility.command_executer("{}".format(CPU)))
            total_cpu_usage += cpu_usage
        return total_cpu_usage

    def get_rss_for_pids(self):
        """This method returns the total rss for the process id.

        Returns:
            float: total_rss

        """
        total_rss = 0
        for process_id in self.process_ids:
            RSS = "ps -p {} -o rss=".format(process_id)
            rss_usage = float(Utility.command_executer("{}".format(RSS)))
            total_rss += rss_usage
        return total_rss

    def get_vsz_for_pids(self):
        """This method returns the total vsz for the process id.

        Returns:
            float: total_vsz

        """
        total_vsz = 0
        for process_id in self.process_ids:
            VSZ = "ps -p {} -o vsize=".format(process_id)
            vsz_usage = float(Utility.command_executer("{}".format(VSZ)))
            total_vsz += vsz_usage
        return total_vsz

    def get_time_stamp(self):
        """This method returns date and time.

        Args:

        Returns:
            int - date and time

        """

        try:
            return (int(self._start_time) + int(self._end_time))/2
        except ValueError:
            return -1

    def get_cpu(self):
        """This method returns cpu usage.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            float: cpu usage

        """
        try:
            core = float(Utility.command_executer("{}".format(CPU_CORE)))
            return float(self._cpu/core)
        except ValueError:
            return -1

    def get_rss(self):
        """This method returns rss usage.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int: rss usage

        """
        try:
            return int(self._rss)
        except ValueError:
            return -1

    def get_vsz(self):
        """This method returns vsz usage.

        Args:
            self (instance) - it refers to the variables and methods of the
            same class.

        Returns:
            int: vsz usage

        """
        try:
            return int(self._vsz)
        except ValueError:
            return -1

    def send_mme_hss_sys_stats(self):
        """This method sends the mme hss system stats information to pushgateway and stats collector.

        Args:
           None

        Returns:
            None
        """
	    #Note: Field name should be in [a-zA-Z_:][a-zA-Z0-9_:]* regex pattern
        #Examples: 
        #1. Field which contains with bracket not supported --> "cpu(%)": self.get_cpu()
        #2. Field which starts with number not supported --> 5xxx_ans_sent":  10
        mme_hss_sys_dict = {
                    "timeStamp":self.get_time_stamp(),
                    "CPU":self.get_cpu(),
                    "RSS":self.get_rss(),
                    "VSZ":self.get_vsz(),
                    "collectionName": COLLECTION_NAME,
                    "otherInfo":{"scriptName": SCRIPT_NAME}
		        }
        self._client_obj.send_stats_to_server(mme_hss_sys_dict)

if __name__ == '__main__':
    DURATION = Utility.get_duration(DURATION_KEY)
    STAT_OBJ = ClientStatsSender()
    SYS_OBJ = MmeHssSysStats(STAT_OBJ)
    DONE = True

    def sigint_handler(signum, frame):
        """ This method catch the signal and perform respective action.
        """
        global DONE
        DONE = False

    signal.signal(signal.SIGINT, sigint_handler)

    while DONE:
        START_TIME = time.time()
        SYS_OBJ.execute_mmeHssSysStats()
        END_TIME = time.time()
        SYS_OBJ.send_mme_hss_sys_stats()
        time.sleep(DURATION-(END_TIME-START_TIME))
