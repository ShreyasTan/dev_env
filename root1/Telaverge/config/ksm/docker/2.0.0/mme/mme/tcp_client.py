""" Module to handle tcp client code """
import os
import time
import socket
import traceback
import select
import threading
from queue import Queue, Empty
from pyDiameter.pyDiaMessage import *

import mme.mme.custom_exception as exception
from mme.mme.constants import Constants
from mme.mme.mme_log import MMELogMgr

class TcpClient:
    """ Class to Handle tcp client requests"""
    def __init__(self):
        """ Initilization of the class """
        self._log = MMELogMgr("TcpClient").get_logger()
        self._log.debug(">")
        self.server_port = Constants.LB_PORT
        self.regal_root_path = os.getenv("REGAL_ROOT_PATH")
        self.requests = 0
        self.responses = 0
        if not self.regal_root_path:
            self.server_addr = Constants.HOST_IP
        else:
            self.server_addr = Constants.LB_SERVICE_NAME
        self._msg_lng = 1580
        self._task_queue = Queue()
        self._recv_flag = True

        self.recv_thread = threading.Thread(target=self.recv_response, args=())
        self.recv_thread.setName("ResponseRecvThread")
        self.recv_thread.start()
        self._log.debug("<")

    def set_e2e_hbh(self, req_buff):
        """ This method is used to set end 2 end and hop by hop id
        """
        self._log.debug(">")
        request = DiaMessage()
        request.decode(req_buff)
        request.generateE2EID()
        request.generateHBHID()
        self._log.debug("<")
        return request

    def encode_message(self, req_buff):
        """ This method is used to encode the ULR bytes
        """
        self._log.debug(">")
        request = self.set_e2e_hbh(req_buff)
        encoded_message = request.encode()
        self._log.debug("<")
        return encoded_message

    def initilize(self):
        """ Method to initilize the required self
            variables for the class

        Returns:
            None

        """
        self._log.debug(">")
        self.client = self.create_client_socket()
        self._log.debug("<")

    def create_client_socket(self):
        """This create the socket.

        Args:

        Returns:
            instane: socket object

        """
        self._log.debug(">")
        try:
            socket_obj =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect((self.server_addr, self.server_port))
            socket_obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            socket_obj.setblocking(0)
            self._log.debug("<")
        except socket.error as ex:
            err_msg = "Failed to create the connection with server %s-%s "\
                            "and exception %s",self.server_addr, self.server_port, ex
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.TcpConnectionFailed(str(err_msg))
        self._log.debug("<")
        return socket_obj

    def close_client_connection(self):
        """ Method close the client connection.

        Returns:
            None

        """
        self._log.debug(">")
        try:
            self.client.close()
        except socket.error:
            pass
        self._log.debug("<")

    def recv_response(self):
        """
        """
        self._log.debug(">")
        client_obj = None
        buff = b''
        while self._recv_flag:
            try:
                try:
                    client_obj = self._task_queue.get(timeout=0.001)
                except Empty:
                    pass
                except Exception as ex:
                    self._log.error("the exception %s", str(ex))

                if client_obj:
                    infds, outfds, errfds = select.select([client_obj],
                            [], [], 1)
                    if infds:
                        try:
                            received_data = client_obj.recv(2048)
                        except BlockingIOError as ex:
                            break
                        if not received_data:
                            pass

                        buff = buff + received_data
                        received_data = b''
                        while True:
                            if len(buff) < self._msg_lng:
                                break
                            msg = buff[:self._msg_lng]
                            buff = buff[self._msg_lng:]
                            self.responses = self.responses + 1
            except Exception as ex:
                self._log.error("Traceback %s", traceback.format_exc())
                self._log.debug("<")
        self._log.debug("<")

    def send_message(self, msg, brust_size, msg_duration, interval_time):
        """This method send the messages to server.

        Args:
            msg(str): The message needs to be send
            count(int): Number of message needs to send
            interval_time(int): Interval time between messages

        Returns:
            None:

        """
        self._log.debug(">")
        try:
            client_socket = []
            self.client = self.create_client_socket()
            self._task_queue.put(self.client)

            start_time = time.time()
            end_time = start_time + int(msg_duration)

            while end_time > time.time():
                for brust in range(0, int(brust_size)):
                    encoded_msg = self.encode_message(msg)
                    self.client.sendall(encoded_msg)
                    self.requests = self.requests + 1
                time.sleep(int(interval_time)/1000)
            self._log.debug("<")
        except Exception as ex:
            self._log.error("Failed to send message %s", ex)
            self._log.error("Trace back: %s", traceback.format_exc())
            self._log.debug("<")

    def get_status(self):
        """ Retuns overall status odf how many msgs
        are sent and received .

        Returns:
            int: How many msgs are sent and received

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.requests, self.responses, socket.gethostname()

    def reset_counter(self):
        """ Method to reset the messages count

        Retuns:
            None

        """
        self._log.debug(">")
        self.requests = 0
        self.responses = 0
        self._log.debug("<")

    def stop_recv_thread(self):
        """
        """
        self._log.debug(">")
        self._recv_flag = False
        if self.recv_thread:
            self.recv_thread.join()
        self._log.debug("<")
