# -*- encoding: utf-8 -*-
"""
kami.app.cli.commands module

"""
import argparse

from kami.core import coring

import pysodium

parser = argparse.ArgumentParser(description='Print a new random passcode')
parser.set_defaults(handler=lambda args: handler(args))


async def handler(_):
    salt = passcode()
    print(salt)
    return salt


def passcode():
    """
    Create a valid passcode and return it as a string
    """

    return (coring.Salter(raw=pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)).qb64)
