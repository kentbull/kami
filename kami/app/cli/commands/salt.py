# -*- encoding: utf-8 -*-
"""
kami.app.cli.commands module

"""
import argparse

import pysodium

from kami.core import coring

parser = argparse.ArgumentParser(description='Print a new random passcode')


def handler(_):
    """
    Return a list of coroutines to be run to create a passcode.
    The coroutines will be run by the event loop.

    :param _: no args, just create a passcode
    :return: list of one coroutine that creates a passcode
    """
    return [passcode()]


parser.set_defaults(handler=handler)


async def passcode() -> str:
    """
    Create a valid passcode and return it as a string
    """
    salt = coring.Salter(
        raw=pysodium.randombytes(
            pysodium.crypto_sign_SEEDBYTES
        )
    ).qb64

    print(salt)
    return salt
