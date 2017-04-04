import ssl
import sys
import asyncio

import cno


async def main(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    resp = await cno.request(loop, 'GET', url, ssl_ctx=ctx)
    await print_response([('GET', url)], resp)
    resp.conn.close()


async def print_response(chain, rsp):
    head = ' \033[1;35m->\033[0m '.join('\033[1;35m{}\033[0m {}'.format(method, url) for method, url in chain)
    print('>>>', head, '\033[1;3{}m{} (http/{})\033[39m'.format(
        2 if 200 <= rsp.code < 300 else
        1 if 400 <= rsp.code < 600 else 2, rsp.code, 2 if rsp.conn.is_http2 else 1))
    for k, v in rsp.headers:
        print('    \033[1;34m{}\033[0m: {}'.format(k, v))

    payload = len(await rsp.payload.read())
    print('    \033[1;36mpayload\033[0m: {} bytes'.format(payload))

    async for push in rsp.pushed:
        print('>>> \033[1;35mpush {}\033[0m {}'.format(push.method, push.path))
        for k, v in push.headers:
            print('    \033[1;34m{}\033[0m: {}'.format(k, v))
        await print_response(chain + [(push.method, push.path)], (await push.response))


if len(sys.argv) != 2:
    exit('usage: {0} <url>'.format(*sys.argv))

loop = asyncio.get_event_loop()
loop.run_until_complete(main(sys.argv[1]))
