import asyncio
from typing import List, Coroutine

import multicommand
import uvloop

from kami.app import directing
from kami.app.cli import commands

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


async def kamiCli():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, 'handler'):
        parser.print_help()
        return

    try:
        tasks: List[Coroutine] = args.handler(args)
        # replace with asyncio event loop
        results = await directing.runController(tasks=tasks)

    except Exception as ex:
        import os
        if os.getenv('DEBUG_KLI'):
            import traceback
            traceback.print_exc()
        else:
            print(f"ERR: {ex}")
        return -1


def main():
    uvloop.install()
    asyncio.run(kamiCli())


if __name__ == "__main__":
    main()
