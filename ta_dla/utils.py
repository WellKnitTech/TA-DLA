"""Shared utility functions for TA-DLA."""
# TODO: Implement logging, config helpers, etc. 

import logging
import os

def get_case_logger(case_dir, log_name='downloader.log'):
    """
    Returns a logger that writes to the case's logs directory and also outputs to the console.
    Args:
        case_dir (str): Path to the case directory.
        log_name (str): Log file name (default: downloader.log).
    Returns:
        logging.Logger: Configured logger instance.
    """
    logs_dir = os.path.join(case_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, log_name)
    logger_name = f'ta_dla.{os.path.basename(case_dir)}.{log_name}'
    logger = logging.getLogger(logger_name)
    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_path)
        file_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        # Console handler
        stream_handler = logging.StreamHandler()
        stream_formatter = logging.Formatter('%(levelname)s %(message)s')
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    # TODO: Add log rotation if needed
    return logger 