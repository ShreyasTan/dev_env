""" Static module to define constants """

class Constants:
    """ Constants class """

    TRIGGER_REQUEST = "trigger_request"
    GET_STATUS = "get_status"
    RESET_COUNT = "reset_counter"
    HSS_POD_COUNT = 2

    HSS_SERVICE_NAME = "hss"
    HSS_PORT = 5014

    LOCAL_HOST = "localhost"
    HOST_IP = "0.0.0.0"
    LB_SERVICE_NAME = "loadbalancer"
    LB_PORT = 5015

    LB_DEBUG_LOG_PATH = "/var/log/loadbalancer/lb_debug.log"
    LB_ERROR_LOG_PATH = "/var/log/loadbalancer/lb_error.log"
    LB_LOG_FORMAT = "format=%(asctime)s - %(thread)d - %(threadName)s - %(module)s - %(funcName)s : %(lineno)d - %(message)s"
