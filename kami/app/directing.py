import asyncio


async def runController(tasks):
    """
    Runs the controller event loop with the given tasks
    :param tasks: the list of tasks to run in this event loop
    :return:
    """
    return await asyncio.gather(*tasks)
