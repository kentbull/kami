import asyncio
import os

import multicommand
import pytest

from kami.app import directing
from kami.app.cli import commands


@pytest.mark.asyncio
async def test_standalone_kami_commands(helpers, capsys):
    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False
    assert os.path.isdir("~/.keri/ks/test") is False

    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["salt"])
    assert args.handler is not None
    tasks = [args.handler(args)]

    results = await directing.runController(tasks=tasks)
    assert len(results) > 0
    assert len(results[0]) == 24
