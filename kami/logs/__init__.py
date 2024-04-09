# -*- encoding: utf-8 -*-
"""
kami.logs package

"""
# Setup module global ogler as package logger factory. This must be done on
# import to ensure global is defined so all modules in package have access to
# loggers via logs.ogler.getLoggers().
# May always change level and reopen log file if need be.

from . import ogling

# initialize global ogler at kami.logs.ogler always instantiated by default
ogler = ogling.initOgler(prefix='kami', syslogged=False)  # init only runs once on import
