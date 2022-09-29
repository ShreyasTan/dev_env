import sys
import socket
import select
import random
import os

from load_balancer.load_balancer.lb_log import LBLogMgr
from load_balancer.load_balancer.constants import Constants
from itertools import cycle
import traceback

class LoadBalancer(object):
    """ Socket implementation of a load balancer. """

    def __init__(self):
        self._log = LBLogMgr("LoadBalancer").get_logger()
        self._log.debug(">")
        self.regal_root_path = os.getenv("REGAL_ROOT_PATH")
        self._recv = 0
        self._reponse = 0
        self.cli_buffer_data = b''
        self.ser_buffer_data = b''

        if not self.regal_root_path:
            self.addr = Constants.HOST_IP
            self.port = Constants.LB_PORT
            self.server_pool = [(Constants.HOST_IP, Constants.HSS_PORT)]
        else:
            self.addr = Constants.HOST_IP
            self.port = Constants.LB_PORT
            self.server_pool = [(Constants.HSS_SERVICE_NAME, Constants.HSS_PORT)]

        self.flow_table = dict()
        self.sockets = list()

        self.cs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cs_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs_socket.bind((self.addr, self.port))
        self.cs_socket.listen(128)
        self.sockets.append(self.cs_socket)
        self._log.debug("<")

    def start(self):
        """ Method start the load balancer server """
        self._log.debug(">")
        while True:
            read_list, write_list, exception_list = select.select(self.sockets,
                    [], [])
            for sock in read_list:
                if sock == self.cs_socket:
                    self._log.debug("Flow start")
                    self.on_accept()
                    self._log.debug("<")
                    break
                else:
                    try:
                        data = sock.recv(2048)
                        if data:
                            self._log.debug("Recevied data from %s to lb %s",
                                    sock.getpeername(), sock.getsockname())
                            self.on_recv(sock, data)
                        else:
                            self.on_close(sock)
                            self._log.debug("<")
                            break
                    except Exception as ex:
                        self.on_close(sock)
                        self._log.debug("<")
                        break

    def on_accept(self):
        """ Method select the server and pass the message to respective
            server.

        Returns:
            None

        """
        self._log.debug(">")
        server_sockets = []
        client_socket, client_addr = self.cs_socket.accept()
        self._log.debug("Connected client is %s : %s ", client_addr,
                client_socket.getsockname())

        try:
            if not self.regal_root_path:
                for addr in self.server_pool:
                    ss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ss_socket.connect(addr)
                    server_sockets.append(ss_socket)
                    self._log.debug("Connected to server %s - "\
                        "%s", ss_socket.getsockname(),
                        ss_socket.getpeername())
            else:
                while len(server_sockets) < Constants.HSS_POD_COUNT:
                    for addr in range(0, Constants.HSS_POD_COUNT):
                        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        ss_socket.connect(self.server_pool[0])
                        right_sock = False
                        for sock_obj in server_sockets:
                            if sock_obj.getsockname() == ss_socket.getsockname():
                                right_sock = True
                                break
                        if not right_sock:
                            server_sockets.append(ss_socket)
                            self._log.debug("Connected to server %s",ss_socket.getsockname())
                            self._log.debug("<")
            self._log.debug("Exited while loop- on_accept with server set %s",
                    server_sockets)

        except socket.error as ex:
            self._log.error("Cannot establish connection with remote server"\
                            " %s-%s Error: %s", addr, ex,
                            traceback.format_exc())
            self._log.debug("closing connection with client %s", client_addr)
            client_socket.close()
            self._log.debug("<")
            return

        self.sockets.append(client_socket)
        self.sockets.extend(server_sockets)

        self.flow_table[client_socket] = server_sockets
        self.round_robin_iter = cycle(server_sockets)
        for sock_addr in server_sockets:
            self.flow_table[sock_addr] = client_socket
        self._log.debug("<")

    def on_recv(self, sock, data):
        """ Method recevie packets from the server and send back to
        response to respective client

        Args:
            sock:
            data:

        Returns:
            None

        """
        self._log.debug(">")
        to_cli = False
        self._log.debug("Recevied data from %s-%s", sock.getpeername(),
                sock.getsockname())
        remote_sockets = self.flow_table[sock]
        buffer_data = b''
        if isinstance(remote_sockets, list):
            remote_socket = self.select_server(self.round_robin_iter)
            msg_len = 692
            self.ser_buffer_data = self.ser_buffer_data + data
            buffer_data = self.ser_buffer_data
        else:
            remote_socket = remote_sockets
            msg_len = 1580
            self.cli_buffer_data = self.cli_buffer_data + data
            buffer_data = self.cli_buffer_data
            to_cli = True

        while True:
            if len(buffer_data) < msg_len:
                self._log.debug("<")
                break
            message = buffer_data[:msg_len]
            buffer_data = buffer_data[msg_len:]
            if to_cli:
                self.cli_buffer_data = self.cli_buffer_data[msg_len:]
            else:
                self.ser_buffer_data = self.ser_buffer_data[msg_len:]
            remote_socket.send(message)
            self._reponse = self._reponse + 1

        self._log.debug("Sending data to %s-%s", remote_socket.getpeername(), remote_socket.getsockname())
        self._log.debug("sent %s", self._reponse)
        self._log.debug("<")

    def on_close(self, sock):
        """ Method close the connections  with given sock """
        self._log.debug(">")
        self._log.debug("client %s is disconnected", sock.getpeername())
        ss_socket = self.flow_table[sock]
        self.sockets.remove(sock)
        sock.close()

        if isinstance(ss_socket, list):
            for server_sock in ss_socket:
                self.sockets.remove(server_sock)
                server_sock.close()
                del self.flow_table[server_sock]
        else:
            self.sockets.remove(ss_socket)
            ss_socket.close()
            del self.flow_table[ss_socket]
        self._log.debug("<")

    def select_server(self, server_list):
        """ Method select the server using random method """
        self._log.debug(">")
        self._log.debug("<")
        return next(server_list)


if __name__ == '__main__':
    try:
        LoadBalancer().start()
    except KeyboardInterrupt:
        sys.exit(1)

