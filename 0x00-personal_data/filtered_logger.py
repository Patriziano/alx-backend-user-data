#!/usr/bin/env python3
"""Write a function called filter_datum that returns the
log message obfuscated"""
from typing import List
import re
import logging
import os
import mysql.connector


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ constructor method """
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """ filter values in a log record"""
        return filter_datum(self.fields,
                            self.REDACTION,
                            super().format(record),
                            self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """Write a function called filter_datum that returns the
    log message obfuscated"""
    for k in fields:
        message = re.sub(fr'{k}=.+?{separator}',
                         f'{k}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """Implement a get_logger function that takes no
    arguments and returns a logging.Logger object."""
    val = logging.getLogger("user_data")
    val.setLevel(logging.INFO)
    val.propagate = False
    action = logging.StreamHandler()
    action.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    val.addHandler(action)
    return val


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Database credentials should NEVER be stored in code or
    checked into version control. One secure option is to
    store them as environment variable on the application server.
    """
    user_name = os.getenv('PERSONAL_DATA_DB_USERNAME')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    return mysql.connector.connect(user=user_name,
                                   password=password,
                                   host=host,
                                   database=db_name)


def main():
    """This the main function"""
    conn = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * from users")
    fields = [user[0] for user in cursor.description]
    print(fields)

    logger = get_logger()

    for i in cursor:
        list_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(i, fields))
        logger.info(i)

    cursor.close()
    db.close()
