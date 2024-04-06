import asyncio

import uvloop

from kami.app.cli.kami import kamiCli


async def cli():
    await kamiCli()


if __name__ == "__main__":
    uvloop.install()
    asyncio.run(cli())
