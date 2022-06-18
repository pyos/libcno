import ssl
import sys
import asyncio
import itertools
import urllib.parse

import cno


def origin(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname, parsed.port, parsed.scheme


async def main(loop, *urls):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    tasks = []
    conns = []
    for _, g in itertools.groupby(sorted(urls, key=origin), key=origin):
        g = list(g)
        conn = await cno.connect(loop, g[0], ssl_ctx=ctx,
            force_http2=g[0].startswith('h2c:') or g[0].startswith('h2:'))
        conns.append(conn)
        for url in g:
            path = urllib.parse.urlparse(url).path
            tasks.append(asyncio.ensure_future(print_response([('GET', url)], conn.request('GET', path))))
    for task in tasks:
        await task
    for conn in conns:
        conn.close()


async def print_response(chain, rsp):
    rsp = await rsp
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
        await print_response(chain + [(push.method, push.path)], push.response)


if len(sys.argv) < 2:
    exit('usage: {0} <url> ...'.format(sys.argv[0]))

loop = asyncio.new_event_loop()
loop.run_until_complete(main(loop, *sys.argv[1:]))
