"User defined exceptions"

class CustomException(Exception):
    """ Custom exceptions"""

    def __init__(self):
        Exception.__init__(self)

    def __str__(self):
        """Return exception string."""
        return "Custom exception"

class InstallFailed(Exception):
    """ Exception will be thrown when installation is failed
    """

    def __init__(self, error_msg):
        Exception.__init__(self)
        self._error_msg = error_msg

    def __str__(self):
        """ Return exception string. """
        return " {}".format(self._error_msg)

class FailedToStartService(CustomException):
    """ Exception will be thrown when failed to start a service. """

    def __init__(self, message):
        CustomException.__init__(self)
        self.message = message

    def __str__(self):
        """ Return the exception string """
        return "{}".format(self.message)

class FileDoesNotExist(CustomException):
    """ Exception will be thrown when file does not exist. """

    def __init__(self, message):
        CustomException.__init__(self)
        self.message = message

    def __str__(self):
        """ Return the exception string """
        return "{}".format(self.message)

class ServiceNotRunning(CustomException):
    """ Exception will be thrown when service not running. """

    def __init__(self, message):
        CustomException.__init__(self)
        self.message = message

    def __str__(self):
        """ Return the exception string """
        return "{}".format(self.message)

class TestCaseFailed(Exception):
    """ Exception is thrown when the test case/ script execution failed.
    """
    def __init__(self, error_msg):
        Exception.__init__(self)
        self._error_msg = error_msg

    def __str__(self):
        """ Return exception string. """
        return "{}".format(self._error_msg)

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
        super(InsufficientHelperConfig, self).__init__()
        self._key = key
        self._node_name = node_name

    def __str__(self):
        """ Return exception string. """
        return "Key {} for helper is not configured for node {}".format(
                self._key, self._node_name)