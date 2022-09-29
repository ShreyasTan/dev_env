"""
#Add module string.
"""
#!/bin/python
import signal
import time

from stats_utility import Utility, ClientStatsSender

COLLECTION_NAME = "DatetimeServerStats"
DEFAULT_DURATION_KEY = "DatetimeServerStatDuration"
SCRIPT_NAME = "datetimestat"

TIME_STAMP = "date +%s"
YEAR_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::YearRequestCount.0"
MONTH_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::MonthRequestCount.0"
DAY_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::DayOfMonthRequestCount.0"
TIME_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::TimeRequestCount.0"
DATE_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::DateAndTimeRequestCount.0"
LOG_CMD = "snmpget -v 2c -c public -M+. localhost:161 DateTimeServer-MIB::LogPathRequestCount.0"


def get_stats_info():
    """ This method returns the collection name and fields which are used in
    this stats.

    Return:
        dict: key=collections name,
              val=Fileds the

    """
    fields = ["YearRequestCount", "MonthRequestCount", "DayRequestCount",
              "TimeRequestCount", "DateAndTimeRequestCount", "LogPathRequestCount"]
    #Eg: fileds = ["CPU(%)", "Load"]
    stats_info_dict = {COLLECTION_NAME: fields}
    return stats_info_dict


class DatetimeServerStat(object):
    """
    #Add doc string
    """

    def __init__(self, client):
        """ The DatetimeServerStat initilize Utility class object.

        Args:
            client(instance): Object of the ClientStatsSender class.

        """
        self._client_obj = client
        self._year_request_count = None
        self._month_request_count = None
        self._day_of_month_request_count = None
        self._time_request_count = None
        self._date_and_time_request_count = None
        self._log_path_request_count = None

    def execute_datetimestat(self):
        """This method execute stats commands.
        Take avg of start and end time because execution of all commmands
        takig nearly one second .

        Args:
            None:

        Returns:
            None - Nothing is returned

        """

        self.start_time = Utility.command_executer("{}".format(TIME_STAMP))
        # Add Stats commands here
        self._year_request_count = Utility.command_executer(
            "{}".format(YEAR_CMD))
        self._month_request_count = Utility.command_executer(
            "{}".format(MONTH_CMD))
        self._day_of_month_request_count = Utility.command_executer(
            "{}".format(DAY_CMD))
        self._time_request_count = Utility.command_executer(
            "{}".format(TIME_CMD))
        self._date_and_time_request_count = Utility.command_executer(
            "{}".format(DATE_CMD))
        self._log_path_request_count = Utility.command_executer(
            "{}".format(LOG_CMD))
        self.end_time = Utility.command_executer("{}".format(TIME_STAMP))

    def get_year_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._year_request_count[-1])
        except:
            return -1

    def get_month_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._month_request_count[-1])
        except:
            return -1

    def get_day_of_month_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._day_of_month_request_count[-1])
        except:
            return -1

    def get_time_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._time_request_count[-1])
        except:
            return -1

    def get_date_and_time_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._date_and_time_request_count[-1])
        except:
            return -1

    def get_log_path_request_count(self):
        """This method returns count
        Args:

        Returns:
            int - count
        """
        try:
            return int(self._log_path_request_count[-1])
        except:
            return -1

    def get_time_stamp(self):
        """This method returns date and time.

        Args:

        Returns:
            int - date and time

        """
        try:
            return (int(self.start_time) + int(self.end_time))/2
        except ValueError:
            return -1

    def send_datetimestat(self):
        """This method sends the datetime stats information to pushgateway
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
            "timeStamp": self.get_time_stamp(),
            "YearRequestCount": self.get_year_request_count(),
            "MonthRequestCount": self.get_month_request_count(),
            "DayRequestCount": self.get_day_of_month_request_count(),
            "TimeRequestCount": self.get_time_request_count(),
            "DateAndTimeRequestCount": self.get_date_and_time_request_count(),
            "LogPathRequestCount": self.get_log_path_request_count(),
            "collectionName": COLLECTION_NAME,
            "otherInfo": {"ScriptName": SCRIPT_NAME}
        }
        self._client_obj.send_stats_to_server(sys_dict)

if __name__ == '__main__':
    DURATION = Utility.get_duration(DEFAULT_DURATION_KEY)
    CLIENT_OBJ = ClientStatsSender()
    STATS_OBJ = DatetimeServerStat(CLIENT_OBJ)
    DONE = True

    def sigint_handler(signum, frame):
        """ This method catch the signal and perform respective action.
        """
        global DONE
        DONE = False

    signal.signal(signal.SIGINT, sigint_handler)

    while DONE:
        START_TIME = time.time()
        STATS_OBJ.execute_datetimestat()
        END_TIME = time.time()
        STATS_OBJ.send_datetimestat()
        time.sleep(DURATION-(END_TIME-START_TIME))
