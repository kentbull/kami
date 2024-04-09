# -*- encoding: utf-8 -*-
"""
kami.app.httping module

"""
from urllib import parse

import aiohttp

from .. import logs

logger = logs.ogler.getLogger()


class Clienter:
    """
    Async implementation of Clienter class using aiohttp
    """

    def __init__(self):
        self.session = aiohttp.ClientSession()

    async def request(self, method, url, body=None, headers=None) -> dict| None:
        purl = parse.urlparse(url)
        full_url = f"{purl.scheme}://{purl.netloc}{purl.path}"
        if purl.query:
            full_url += f"?{purl.query}"

        try:
            async with self.session.request(method=method, url=full_url, data=body,
                                            headers=headers) as response:
                return await response.json()
        except Exception as e:
            message = f"error making request: {e}"
            logger.error(message)
            return None

    async def close(self):
        await self.session.close()
