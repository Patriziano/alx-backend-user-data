#!/usr/bin/env python3
"""implement a hash_password function that expects one string argument
name password and returns a salted, hashed password, which is a byte stringd"""

import logging
import bcrypt


def hash_password(password: str) -> bytes:
    """This is a hash pwd function"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """This is is valid function"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except Exception as e:
        logging.error("Error in password validation: {}".format(e))
        return False
