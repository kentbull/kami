# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import logging
import os

import pytest

from kami import kering
from kami import logs
from kami.logs import ogling


def test_openogler():
    """
    Test context manager openOgler
    """
    # used context manager to directly open an ogler  Because loggers are singletons
    # it still affects loggers.

    with ogling.openOgler(level=logging.DEBUG) as ogler:  # default is temp = True
        assert isinstance(ogler, ogling.Ogler)
        assert ogler.name == "test"
        assert ogler.level == logging.DEBUG
        assert ogler.temp
        assert ogler.prefix == 'kami'
        assert ogler.headDirPath == ogler.HeadDirPath == "/usr/local/var"
        assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
        assert ogler.dirPath.endswith("_temp")
        assert ogler.path.endswith("/test.log")
        assert ogler.opened

        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")


        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n')


        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")

        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n'
                                'kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n')

    assert not ogler.opened
    logs.ogler.resetLevel(level=logs.ogler.level)


    with ogling.openOgler(name='mine', temp=False, level=logging.DEBUG) as ogler:
        assert isinstance(ogler, ogling.Ogler)
        assert ogler.name == "mine"
        assert ogler.level == logging.DEBUG
        assert not ogler.temp
        assert ogler.prefix == 'kami'
        assert ogler.headDirPath == ogler.HeadDirPath == "/usr/local/var"
        assert ogler.dirPath in ["/usr/local/var/kami/logs", os.path.expanduser("~/.kami/logs")]
        assert ogler.path in ['/usr/local/var/kami/logs/mine.log', os.path.expanduser("~/.kami/logs/mine.log")]
        assert ogler.opened

        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")


        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n')


        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")

        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n'
                                'kami: Test logger at debug level\n'
                                'kami: Test logger at info level\n'
                                'kami: Test logger at error level\n')

    assert not ogler.opened
    assert os.path.exists(ogler.path)
    os.remove(ogler.path)
    assert not os.path.exists(ogler.path)
    logs.ogler.resetLevel(level=logs.ogler.level)

    """End Test"""



def test_ogler():
    """
    Test Ogler class instance that builds loggers
    """
    ogler = ogling.Ogler(name="test", )
    assert ogler.path is None
    assert not ogler.opened
    assert ogler.level == logging.ERROR  # default is ERROR
    assert ogler.dirPath is None
    assert ogler.path is None

    # logger console: Only Error should log  because level ERROR
    # logger file: Nothing should log because .path not created
    logger = ogler.getLogger()
    assert len(logger.handlers) == 2
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")


    ogler.level = logging.DEBUG
    # logger console: All should log  because level DEBUG
    # logger file: nothing should log because .path still not created
    logger = ogler.getLogger()
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # create ogler with opened path
    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True,
                         reopen=True, clear=True)
    assert ogler.level == logging.DEBUG
    assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    assert ogler.opened
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    assert len(logger.handlers) == 3
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    ogler.temp = False  # trick it to not clear on close
    ogler.close()  # but do not clear
    assert os.path.exists(ogler.path)
    assert not ogler.opened
    ogler.temp = True  # restore state

    # Test reopen but not clear so file still there
    ogler.reopen(temp=True)
    assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    assert ogler.opened
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    assert len(logger.handlers) == 3
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n'
                            'kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')


    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)
    assert not ogler.opened

    # test selective ogler handlers
    with pytest.raises(kering.OglerError):
        ogler = ogling.Ogler(name="test", consoled=False, syslogged=False, filed=False)


    # Only console
    # create ogler with opened path
    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True,
                         reopen=True, clear=True, syslogged=False, filed=False)
    assert ogler.level == logging.DEBUG
    assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    assert ogler.opened
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    assert len(logger.handlers) == 1
    assert logger.handlers[0] == ogler.baseConsoleHandler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # Only file
    # create ogler with opened path
    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True,
                         reopen=True, clear=True, syslogged=False, consoled=False)
    assert ogler.level == logging.DEBUG
    assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    assert ogler.opened
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    assert len(logger.handlers) == 1
    assert logger.handlers[0] == ogler.baseFileHandler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    path = ogler.path
    assert ogler.opened  # should be open before closing
    ogler.close(clear=True)
    assert not os.path.exists(path)
    assert not ogler.opened  # should not be open after closing

    logs.ogler = ogling.initOgler(prefix='kami', syslogged=False)  # reset logs.ogler to defaults
    """End Test"""


def test_init_ogler():
    """
    Test initOgler function for ogler global
    """
    #defined by default in help.__init__ on import of ogling
    assert isinstance(logs.ogler, ogling.Ogler)
    assert not logs.ogler.opened
    assert logs.ogler.level == logging.CRITICAL  # default
    assert logs.ogler.dirPath is None
    assert logs.ogler.path is None

    # nothing should log to file because .path not created and level critical
    # # nothing should log to console because level critical
    logger = logs.ogler.getLogger()
    assert len(logger.handlers) == 1  # should be one because syslogged=False in logs.__init__
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    logs.ogler.level = logging.DEBUG
    # nothing should log because .path not created despite loggin level debug
    logger = logs.ogler.getLogger()
    assert len(logger.handlers) == 1  # should be one because syslogged=False in logs.__init__
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    #reopen ogler to create path
    logs.ogler.reopen(temp=True, clear=True)
    assert logs.ogler.opened
    assert logs.ogler.level == logging.DEBUG
    assert logs.ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert logs.ogler.dirPath.endswith("_temp")
    assert logs.ogler.path.endswith("/main.log")
    logger = logs.ogler.getLogger()
    assert len(logger.handlers) == 2  # should be two because syslogged=False in logs.__init__
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(logs.ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    ogler = logs.ogler = ogling.initOgler(name="test", level=logging.DEBUG,
                                          temp=True, reopen=True, clear=True)
    assert ogler.opened
    assert ogler.level == logging.DEBUG
    assert ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    logger = ogler.getLogger()
    assert len(logger.handlers) == 3  # should be three because syslogged=True in default
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)

    logs.ogler = ogling.initOgler(prefix='kami', syslogged=False)  # reset logs.ogler to defaults
    """End Test"""


def test_set_levels():
    """
    Test setLevel on preexisting loggers
    """
    #defined by default in help.__init__ on import of ogling
    assert isinstance(logs.ogler, ogling.Ogler)
    assert not logs.ogler.opened
    assert logs.ogler.level == logging.CRITICAL  # default
    assert logs.ogler.path is None
    logger = logs.ogler.getLogger()
    assert len(logger.handlers) == 1  # should be one because syslogged=False in logs.__init__

    # logger console: nothing should log  because level CRITICAL
    # logger file: nothing should log because .path not created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # test reset levels without recreating logger
    logs.ogler.resetLevel(level=logging.DEBUG, globally=True)

    # logger console: All should log  because level DEBUG
    # logger file: Nothing should log because .path not created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # reopen ogler to create path
    logs.ogler.reopen(temp=True, clear=True)
    assert logs.ogler.opened
    assert logs.ogler.level == logging.DEBUG
    assert logs.ogler.dirPath.startswith("/tmp/kami/logs/test_")
    assert logs.ogler.dirPath.endswith("_temp")
    assert logs.ogler.path.endswith("/main.log")
    # recreate loggers to pick up file handler
    logger = logs.ogler.getLogger()
    assert len(logger.handlers) == 2  # should be two because syslogged=False in logs.__init__

    # logger console: All should log  because level DEBUG
    # logger file: All should log because .path created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(logs.ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')


    # force reinit on different path with syslogged=True, so 2 and then later 3 loggers after reopen
    ogler = logs.ogler = ogling.initOgler(name="test", level=logging.DEBUG,
                                          temp=True, reopen=True, clear=True)
    assert ogler.opened
    assert ogler.level == logging.DEBUG
    dirpath = ogler.dirPath
    assert (dirpath.startswith("/tmp/kami/logs/test_")
            or dirpath.startswith(os.path.expanduser("~/.kami/logs/test_")))
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith("/test.log")
    # Still have 2 handlers
    assert len(logger.handlers) == 2  # should be two because syslogged=False in logs.__init__

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: None should log because old path on file handler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # recreate loggers to pick up new path
    logger = ogler.getLogger()
    assert len(logger.handlers) == 3  # Should be three because default syslogged=True

    # logger console: All should log  because level DEBUG
    # logger file: All should log because new path on file handler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('kami: Test logger at debug level\n'
                            'kami: Test logger at info level\n'
                            'kami: Test logger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)

    logs.ogler = ogling.initOgler(prefix='kami', syslogged=False)  # reset logs.ogler to defaults
    """End Test"""


if __name__ == "__main__":
    test_openogler()
    test_ogler()
    test_init_ogler()
    test_set_levels()
