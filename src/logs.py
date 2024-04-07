import logging

class CustomFormatter(logging.Formatter):

    reset = "\x1b[0m"
    grey = reset + "\x1b[38;20m"
    yellow = reset + "\x1b[33;20m"
    red = reset + "\x1b[31;20m"
    bold_red = reset + "\x1b[31;1m"
    
    dates = "[%(asctime)s]: "
    format = "[%(levelname)s]"
    msg = ": %(message)s"

    FORMATS = {
        logging.DEBUG: grey + dates + yellow + format + grey + msg + reset,
        logging.INFO: grey + dates + grey + format + grey + msg + reset,
        logging.WARNING: grey + dates + yellow + format + grey + msg + reset,
        logging.ERROR: grey + dates + red + format + grey + msg + reset,
        logging.CRITICAL: grey + dates + bold_red + format + grey + msg + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
