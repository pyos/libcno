import sys
import asyncio

import cno


async def main(url):
    resp = await cno.request(loop, 'GET', url)
    await print_response(resp)
    resp.conn.close()


async def print_response(rsp):
    print('>>> \033[1;3{}m{}\033[39m'.format(
        2 if 200 <= rsp.code < 300 else
        1 if 400 <= rsp.code < 600 else 2, rsp.code))
    for k, v in rsp.headers:
        print('    \033[1;34m{}\033[0m: {}'.format(k, v))

    payload = len(await rsp.payload.read())
    print('    \033[1;36mpayload\033[0m: {} bytes'.format(payload))

    async for push in rsp.pushed:
        print('>>> \033[1;35mpush {}\033[0m {}'.format(push.method, push.path))
        for k, v in push.headers:
            print('    \033[1;34m{}\033[0m: {}'.format(k, v))
        await print_response((await push.response))


if len(sys.argv) != 2:
    exit('usage: {0} <url>'.format(*sys.argv))

loop = asyncio.get_event_loop()
loop.run_until_complete(main(sys.argv[1]))
