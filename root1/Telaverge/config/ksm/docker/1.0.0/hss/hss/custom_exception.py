"User defined exceptions"

class ArgsNotPresent(Exception):
    """ Exception will be thrownif expected argument is not present
         in the request
    """
    def __init__(self, expected_arg):
        Exception.__init__(self)
        self.arg_name = expected_arg

    def __str__(self):
        """ Return exception string. """
        return "{} is not present in the request".format(self.arg_name)

class ArgsValueEmpty(Exception):
    """ Exception will be thrown when expected argument valuse is empty
        in the request
    """
    def __init__(self, expected_arg):
        Exception.__init__(self)
        self.arg_name = expected_arg

    def __str__(self):
        """ Return exception string. """
        return "{} is empty in the request".format(self._arg_name)

class TcpConnectionFailed(Exception):
    """ Exception will be thrown when some error occurs during
        creation of client server connection
    """
    def __init__(self, error_msg):
        Exception.__init__(self)
        self.err_msg = error_msg

    def __str__(self):
        """ Return exception string. """
        return "{}".format(self.err_msg)
