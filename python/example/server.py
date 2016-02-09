import sys
import signal
import asyncio

import cno


async def respond(req):
    print('>>> \033[1;35m{}\033[0m {}'.format(req.method, req.path))
    for k, v in req.headers:
        print('    \033[1;34m{}\033[0m: {}'.format(k, v))

    payload = len(await req.payload.read())
    print('    \033[1;36mpayload\033[0m: {} bytes'.format(payload))

    req.push('GET', '/hello')
    await req.respond(200, [('content-length', '14')], b'Hello, World!\n')


async def main(loop, *args, **kwargs):
    server = await loop.create_server(lambda: cno.Server(loop, respond), *args, **kwargs)
    try:
        task = asyncio.Future(loop=loop)
        loop.add_signal_handler(signal.SIGINT, task.cancel)
        await task
    except CancelledError:
        pass
    finally:
        server.close()


if len(sys.argv) != 2 and len(sys.argv) != 4:
    exit('usage: {0} <port> [<certfile> <keyfile>]'.format(*sys.argv))

sctx = None
if len(sys.argv) == 4:
    import ssl
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(certfile=sys.argv[2], keyfile=sys.argv[3])
    sctx.set_npn_protocols(['h2', 'http/1.1'])
    sctx.set_alpn_protocols(['h2', 'http/1.1'])

loop = asyncio.get_event_loop()
loop.run_until_complete(main(loop, '', int(sys.argv[1]), ssl=sctx))
