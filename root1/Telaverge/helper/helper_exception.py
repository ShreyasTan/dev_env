class InvalidConfiguration(Exception):
    """ Exception will be thrown when configuration is invalid
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._error_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return "{}".format(self._error_msg)

class InsufficientHelperConfig(Exception):
    """ Exception will be thrown when insufficient configuration key
    """
    def __init__(self, node_name, key):
        Exception.__init__(self)
        self._key = key
        self._node_name = node_name

    def __str__(self):
        """ Return exception string. """
        return "Key {} for helper is not configured for node {}".format(
            self._key, self._node_name)

class PodsNotScheduled(Exception):
    """ Exception will be raised if pods are not
    scheduled to given node
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class PodsScheduleTimeOut(Exception):
    """ Exception will be raised if timeout happens during
    pods schedule for give node.
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class PodNotFound(Exception):
    """ Exception will be raised if pod with name resource.
    is not found under given release
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class NodeNotFound(Exception):
    """ Exception will be raised if node object is not present
    in the topology object

    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class FailedToStartService(Exception):
    """ Exception will be raised if failed to start the service

    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class FailedToStopService(Exception):
    """ Exception will be raised if failed to stop the service

    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class ServiceAccessDenied(Exception):
    """ Exception is raised if service access is denied
    on any cluster node
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class VIPNotPresent(Exception):
    """ Exception is raised if vip is not configured on the
        given node
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class SentRcvdMesgsCountNotEqual(Exception):
    """ Exception is raised if sent and received count is not matched
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class TestcaseError(Exception):
    """ Exception is raised if test case is raised
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)

class UpdateResourceTimeout(Exception):
    """ Exception is raised if timeout happened
    """
    def __init__(self, err_msg):
        Exception.__init__(self)
        self._err_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return  "{}".format(self._err_msg)
