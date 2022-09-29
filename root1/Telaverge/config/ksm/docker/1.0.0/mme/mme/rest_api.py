""" Module provide the rest api's for

"""
from flask import Flask, jsonify, request
import requests
import logging
import urllib3
import ast

import mme.mme.custom_exception as exception
from mme.mme.tcp_client import TcpClient
from mme.mme.constants import Constants
from mme.mme.mme_log import MMELogMgr

class RESTAPIServer:
    """ This class defined the Rest api's """

    def __init__(self, task_queue, tcp_cli):
        """ initilization of the RESTAPIServer server """
        self._log = MMELogMgr("MMERestAPI").get_logger()
        self._log.debug(">")
        #self._host_ip = IP
        #self._port = PORT
        self._task_queue = task_queue
        self._tcp_cli = tcp_cli
        self._log.debug("<")

    def validate_args_in_request(self, expected_args, request_args):
        """ Method validates the arguments passed are empty and are valid

        Args:
            expected_args(list): Args that needs to be present in the request
            request_args(list): Args that are passed in the request

        Returns:
            None

        Raises:
            ArgsNotPresent:
            ArgsValueEmpty

        """
        self._log.debug(">")
        for ex_argument in expected_args:
            if ex_argument not in request_args:
                self._log.debug("<")
                raise exception.ArgsNotPresent(ex_argument)
            if ex_argument == '':
                self._log.debug("<")
                raise exception.ArgsValueEmpty(ex_argument)
        self._log.debug("<")
        return None

    def validate_result(self, result_list, request, response=''):
        """This function validates the result received from the other modules
        for api and converts to the json format

        Args:
            result_list(list): list of result from regal server api
            response_(str): response code

        Returns:
            dict_(json)

        """
        self._log.debug(">")
        if not result_list[0]:
            out_dict = {"status" : "Failed"}
            if response == 405 or response == 404 or response == 400 or response == 500:
                out_dict.update({"response" : response_})
            else:
                out_dict.update({"response" : '200'})
            out_dict.update({"Reason" : result_list[1]})
            self._log.debug("<")
            return jsonify(out_dict)
        else:
            out_dict = {"status" : "Successful"}
            out_dict.update({"response" : '200'})
            out_dict.update({"data" : result_list[1]})
            self._log.debug("<")
            return jsonify(out_dict)

    def add_task(self, action, args):
        """ Method add the task to task handler queue

        Args:
            action(str): action need to happen
            args(dict): the argemets that required for action

        Returns:
            None

        """
        self._log.debug(">")
        self._log.debug("Adding task %s to task handler", action)
        data = {
                "action": action,
                "args": args
            }
        self._task_queue.put(data)
        self._log.debug("<")

    def rest(self):
        """ this function contain all the REST API'S

        Args:
            None

        Returns:
            RestApplication app

        """
        app = Flask("RESTAPIServer")
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

        @app.route('/send_message', methods=['POST'])
        def send_message():
            """ API to send the message

            Args:
                message(str): Message that need to be send

            Returns:
                result: Result of the request

            """
            self._log.debug(">")
            expected_args = ['duration', 'interval_time', 'brust_size']
            request_args =  request.args
            try:
                self.validate_args_in_request(expected_args, request_args)
            except (exception.ArgsValueEmpty, exception.ArgsNotPresent) as ex:
                self._log.debug("<")
                return self.validate_result([False, str(ex)], request)

            try:
                msg = request.data
            except Exception as ex:
                err_msg = "Given message is not valid : {}".format(ex)
                self._log.debug("<")
                return self.validate_result([False, err_msg], request)

            try:
                int(request.args["duration"])
            except ValueError:
                err_msg = "duration in the request is not an integer"
                self._log.debug("<")
                return self.validate_result([False, err_msg], request)

            try:
                int(request.args["interval_time"])
            except ValueError:
                err_msg = "interval_time in the request is not an integer"
                self._log.debug("<")
                return self.validate_result([False, err_msg], request)

            try:
                int(request.args["brust_size"])
            except ValueError:
                err_msg = "brust_size in the request is not an integer"
                self._log.debug("<")
                return self.validate_result([False, err_msg], request)

            args = {
                "brust_size": request.args["brust_size"],
                "duration": request.args["duration"],
                "interval_time": request.args['interval_time'],
                "msg": msg
                }
            self.add_task(Constants.TRIGGER_REQUEST, args)
            message = "send_message action successfully added to queue"
            self._log.debug("send_meeage action successfully added to queue")
            self._log.debug("<")
            return self.validate_result([True, str(message)], request)

        @app.route('/get_status', methods=['GET'])
        def get_status():
            """ API to send the message

            Args:
                message(str): Message that need to be send

            Returns:
                result: Result of the request

            """
            result = self._tcp_cli.get_status()
            return self.validate_result([True, result], request)

        @app.route('/reset_counter', methods=['POST'])
        def reset_counter():
            """ API to send the message

            Args:
                message(str): Message that need to be send

            Returns:
                result: Result of the request

            """
            self._log.debug(">")
            result = self._tcp_cli.reset_counter()
            message = "Successfully reseted the message count"
            self._log.debug("<")
            return self.validate_result([True, str(message)], request)



        @app.errorhandler(404)
        def page_not_found(error):
            """This function returns error if method doesnot match

            Args:
                error(int): error

            Returns:
                str: failure
            """
            self._log.debug('> ')
            self._log.debug('< ')
            return self._validate_result(
                ["False", "ERROR 404 - The request not found"], 404)

        @app.errorhandler(405)
        def request_type_not_found(error):
            """This function returns error if  type of request(GET/POST) does
            not match

            Args:
                error(int): error

            Returns:
                str: failure
            """
            self._log.debug('> ')
            self._log.debug('< ')
            self._log.error(
                '< ERROR 405 -The Resource does not support the HTTP method in the request')
            return self._validate_result(
                ["False",
                 "ERROR 405 -The Resource does not support the HTTP method in the request"],
                405)


        @app.errorhandler(500)
        def request_not_found(error):
            """This function returns error if rest api is not able to complete
            the request

            Args:
                error(int): error

            Returns:
                str: failure
            """
            self._log.debug('> ')
            self._log.debug('< ')
            self._log.error('Not able to process the request')
            return self._validate_result(
                ["False",
                 "ERROR 500 -Please check the logs the server was not able to process the request"],
                500)


        return app

    def shutdown(self):
        """This function will shutdown the rest api server


        Returns:
            None
        """
        url = "http://{}:{}/shutdown".format(self._host_ip, self._port)
        try:
            requests.get(url)
        except (requests.exceptions.ConnectionError,
                urllib3.exceptions.NewConnectionError,
                urllib3.exceptions.MaxRetryError):
            pass

