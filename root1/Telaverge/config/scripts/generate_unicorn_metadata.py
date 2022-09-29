"""
This script is utilized for generating the metadata (as a csv file)
for Unicorn, by using the stored test details from the node
where it's installed.

Steps of Execution:
1. Configure the necessary data to the dictionary
    stored in the CONFIG variable below.
2. Execute this script using the following command
    'python3 generate_unicorn_metadata.py'

Note:
  -  Please make sure python 3 is installed in the system.
  -  The unicorn service needs to be up and running.
  -  The generated metadata will be stored in csv/ dir as a .csv file.
"""

#!/usr/bin/env python3
import csv
import json
import os
import sys
import urllib.request
from urllib.error import HTTPError

# Configure the required data here
CONFIG = {
    "port": 5000,
    "sutName": "Unicorn",
    "tptfPluginName": "TPTFUnicornPlugin"
}


class Constants:
    CSV_DIR = "./csv"
    MAX_RETRY = 5


class UnicornMetaDataGenerator:
    def __init__(self):
        """
        Constructor initialises using infromation from config.json file.
        """
        self.port = CONFIG["port"]
        self.sut_name = CONFIG["sutName"]
        self.plugin_name = CONFIG["tptfPluginName"]

    def initialise(self):
        """
        Method validates the Unicorn service status
        as part of initialization.

        Returns:
            None
        """
        print("> Initializing...")
        status = self._check_unicorn_service_status()
        if not status:
            print("\tUnicorn service is not up!")
            sys.exit()
        print("\tUnicorn service is up and running")

    def _check_unicorn_service_status(self):
        """
        Method checks for the unicorn service.
        Retries 5 times by restarting the service if not up.

        Returns:
            bool: True/False
        """
        print("\t\tChecking Unicorn service status")
        for i in range(Constants.MAX_RETRY):
            status = os.system('systemctl is-active --quiet unicorn')
            if status == 0:
                return True
            print("\t\t... Retrying")
            os.system('systemctl restart unicorn >/dev/null 2>&1')
        return False

    def generate_csv_file(self):
        """
        Method generates metadata based on the test detailes present.

        Returns:
            None
        """
        print("> Generating meta data")
        test_details = self._fetch_test_details()
        fields = ["testSuiteName", "testCaseName", "thirdPartyPluginName"]
        rows = []
        for test_suite, test_cases in test_details.items():
            for test_case in test_cases:
                row = [str(test_suite), str(test_case), str(self.plugin_name)]
                rows.append(row)
        os.makedirs(Constants.CSV_DIR, exist_ok=True)
        file_name = "{0}.csv".format(str(self.sut_name))
        with open(os.path.join(Constants.CSV_DIR, file_name), 'w') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(fields)
            csv_writer.writerows(rows)
        print("\tCSV file '{0}' generated at dir 'csv/'".format(file_name))

    def _fetch_test_details(self):
        """
        Method utilises the Unicorn API to fetch required test details
        and returns the same.

        Returns:
            dict: Test details for a SUT
        """
        print("\tFetching test details...")
        try:
            test_details = {}
            arg = "tests/{0}/LIST_TEST_SUITES".format(self.sut_name)
            response = self.__send_request(arg)
            if "failureCause" in response:
                print("\t\t...", str(response["failureCause"]))
                sys.exit()
            test_suites = response["tests"]
            for test_suite in test_suites:
                arg = "tests/{0}/{1}/LIST_TEST_CASES".format(
                    self.sut_name, test_suite)
                response = self.__send_request(arg)
                if "failureCause" in response:
                    print("\t\t...", str(response["failureCause"]))
                    sys.exit()
                test_cases = response["tests"]
                test_details.update({test_suite: test_cases})
            print("\t\t... Done")
        except Exception as exc:
            print(str(exc))
            sys.exit()
        return test_details

    def __send_request(self, arg):
        """
        Method communicates with Unicorn's REST API.

        Args:
            arg(str): Endpoint argument
        Returns:
            obj: Response
        """
        address = "http://localhost:{0}/".format(self.port)
        url = address + arg
        try:
            response = urllib.request.urlopen(url)
            json_response = json.load(response)
        except HTTPError as err:
            json_response = json.load(err)
        return json_response


if __name__ == '__main__':
    obj = UnicornMetaDataGenerator()
    obj.initialise()
    obj.generate_csv_file()
