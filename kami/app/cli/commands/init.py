# -*- encoding: utf-8 -*-
"""
kami.kli.commands module

"""
import argparse
import getpass

import kami.app.oobiing
from kami import logs
from kami.app import habbing, configing, oobiing
from kami.app.keeping import Algos
from kami.kering import ConfigurationError
from kami.vdr import credentialing

logger = logs.ogler.getLogger()

parser = argparse.ArgumentParser(description='Create a database and keystore')

# Parameters for basic structure of database
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)
parser.add_argument('--salt', '-s', help='qualified base64 salt for creating key pairs', required=False)
parser.add_argument("--config-dir", "-c", dest="configDir", help="directory override for configuration data")
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default=None,
                    help="configuration filename override")

# Parameters for Manager creation
# passcode => bran (salt)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--nopasscode', help='create an unencrypted keystore', action='store_true')
parser.add_argument('--aeid', '-a', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                         'and encryption of secrets in keystore', default=None)
parser.add_argument('--seed', '-e', help='qualified base64 private-signing key (seed) for the aeid from which the '
                                         'private decryption key may be derived', default=None)

def handler(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """
    init = InitCmd(args).initialize()
    return [init]

parser.set_defaults(handler=handler, transferable=True)


class InitCmd:

    def __init__(self, args):
        self.args = args

    async def initialize(self):
        print("Initializing KERI database and keystore...")
        args = self.args
        name = args.name
        if name is None or name == "":
            raise ConfigurationError("Name is required and can not be empty")

        base = args.base
        temp = args.temp
        bran = args.bran
        configFile = args.configFile
        configDir = args.configDir

        if not args.nopasscode and not bran:
            print("Creating encrypted keystore, please enter your 22 character passcode:")
            while True:
                bran = getpass.getpass("Passcode: ")
                retry = getpass.getpass("Re-enter passcode: ")

                if bran != retry:
                    print("Passcodes do not match, try again.")
                else:
                    break

        kwa = dict()
        kwa["salt"] = args.salt
        kwa["bran"] = bran
        kwa["aeid"] = args.aeid
        kwa["seed"] = args.seed
        if args.salt is None:
            kwa["algo"] = Algos.randy

        cf = None
        if configFile is not None:
            cf = configing.Configer(name=configFile,
                                    base="",
                                    headDirPath=configDir,
                                    temp=False,
                                    reopen=True,
                                    clear=False)

        hby = habbing.Habery(name=name, base=base, temp=temp, cf=cf, **kwa)
        rgy = credentialing.Regery(hby=hby, name=name, base=base, temp=temp)

        print("KERI Keystore created at:", hby.ks.path)
        print("KERI Database created at:", hby.db.path)
        print("KERI Credential Store created at:", rgy.reger.path)
        if hby.mgr.aeid:
            print("\taeid:", hby.mgr.aeid)

        # oc = hby.db.oobis.cntAll()
        # if oc:
        #     print(f"\nLoading {oc} OOBIs...")
        #
        #     # todo add to async loop
        #     obi = kami.app.oobiing.Oobiery(hby=hby)
        #     print(f"OOBI: {obi}")
        #     # self.extend(obi.doers)
        #
        #     # todo run after keystore creation
        #     while oc > hby.db.roobi.cntAll():
        #         yield 0.25
        #
        #     for (oobi,), obr in hby.db.roobi.getItemIter():
        #         if obr.state in (oobiing.Result.resolved,):
        #             print(oobi, "succeeded")
        #         if obr in (oobiing.Result.failed,):
        #             print(oobi, "failed")
        #
        #     # self.remove(obi.doers)
        #
        # wc = [oobi for (oobi,), _ in hby.db.woobi.getItemIter()]
        # if len(wc) > 0:
        #     print(f"\nAuthenticating {len(wc)} Well-Knowns...")
        #     # todo add to async loop
        #     authn = oobiing.Authenticator(hby=hby)
        #     print(f"Authenticator: {authn}")
        #     # self.extend(authn.doers)
        #
        #     # todo run after keystore creation
        #     while True:
        #         cap = []
        #         for (_,), wk in hby.db.wkas.getItemIter(keys=b''):
        #             cap.append(wk.url)
        #
        #         if set(wc) & set(cap) == set(wc):
        #             break
        #
        #         yield 0.5

            # self.remove(authn.doers)

        hby.close()
