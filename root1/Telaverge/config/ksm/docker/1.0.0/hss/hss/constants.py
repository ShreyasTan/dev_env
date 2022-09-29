""" Static module to define constants """

class Constants:
    """ Constants class """

    TRIGGER_REQUEST = "trigger_request"
    GET_STATUS = "get_status"
    RESET_COUNT = "reset_counter"
    HSS_POD_COUNT = 4

    HOST_IP = "0.0.0.0"
    HSS_SERVICE_NAME = "hss"
    HSS_PORT = 5014

    LOCAL_HOST = "localhost"
    LOG_CONFIG = "logger/log.json"
    HSS_DEBUG_LOG_PATH = "/var/log/hss/hss_debug.log"
    HSS_ERROR_LOG_PATH = "/var/log/hss/hss_error.log"
    HSS_LOG_FORMAT = "format=%(asctime)s - %(thread)d - %(threadName)s - %(module)s - %(funcName)s : %(lineno)d - %(message)s"
