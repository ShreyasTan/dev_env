""" Static module to define constants """

class Constants:
    """ Constants class """

    TRIGGER_REQUEST = "trigger_request"
    GET_STATUS = "get_status"
    RESET_COUNT = "reset_counter"

    HOST_IP = "0.0.0.0"
    MME_SERVICE_NAME = "mme"
    MME_REST_API_PORT = 5013

    LOCAL_HOST = "localhost"
    LB_SERVICE_NAME = "loadbalancer"
    LB_PORT = 5015

    MME_DEBUG_LOG_PATH = "/var/log/mme/mme_debug.log"
    MME_ERROR_LOG_PATH = "/var/log/mme/mme_error.log"
    MME_LOG_FORMAT = "format=%(asctime)s - %(thread)d - %(threadName)s - %(module)s - %(funcName)s : %(lineno)d - %(message)s"
