import asyncio
import urllib.parse

try:
    import ssl
except ImportError:
    ssl = None

from . import raw


class Channel (asyncio.Queue):
    closed = False

    def close(self):
        self.closed = True

    def put_nowait(self, x):
        if self.closed:
            raise BrokenPipeError('this channel is closed')
        super().put_nowait(x)

    async def __aiter__(self):
        return self

    async def __anext__(self):
        if self.empty() and self.closed:
            raise StopAsyncIteration
        return (await self.get())


class Request:
    def __init__(self, conn, stream, method, path, headers, payload):
        self.conn     = conn
        self.stream   = stream
        self.method   = method
        self.path     = path
        self.headers  = headers
        self.payload  = payload

    async def respond(self, code, headers, data):
        # XXX perhaps imbuing HEAD with a special meaning is a task
        #     for a web framework instead?
        have_data = data and self.method != 'HEAD'
        # TODO if this is a pipelined HTTP/1.1 request, wait until the previous one
        #      is responded to.
        self.conn.write_message(self.stream, code, '', '', headers, not have_data)
        if have_data:
            await self.conn.write_all_data(self.stream, data, True)

    def push(self, method, path, headers=[]):
        copy = {':authority', ':scheme'} - {k for k in headers}
        head = [(k, v) for k, v in self.headers if k in copy]
        head.extend(headers)
        self.conn.write_push(self.stream, method, path, head)


class Response:
    def __init__(self, conn, stream, code, headers, payload, pushed):
        self.conn    = conn
        self.stream  = stream
        self.code    = code
        self.headers = headers
        self.payload = payload
        self.pushed  = pushed

    def cancel(self, code=raw.CNO_RST_CANCEL):
        self.conn.write_reset(self.stream, code)


class Push:
    def __init__(self, conn, stream, method, path, headers, promise):
        self.conn     = conn
        self.stream   = stream
        self.method   = method
        self.path     = path
        self.headers  = headers
        self.promise  = promise

    @property
    async def response(self):
        return (await asyncio.shield(self.promise, loop=self.conn.loop))

    def cancel(self, code=raw.CNO_RST_CANCEL):
        self.conn.write_reset(self.stream, code)


class Connection (raw.Connection, asyncio.Protocol):
    def __init__(self, loop, is_server):
        super().__init__(is_server)
        self.loop     = loop
        self.payloads = {}  # id -> StreamReader
        self.pushreqs = {}  # id -> push channel
        self.handles  = {}  # id -> handling task (server) or response promise (client)
        self.flowctl  = {}  # id -> flow open promise

    def connection_made(self, transport):
        self.transport = transport
        socket = transport.get_extra_info('ssl_object')
        super().connection_made(socket is not None and (
            (ssl.HAS_ALPN and socket.selected_alpn_protocol() == 'h2') or
            (ssl.HAS_NPN  and socket.selected_npn_protocol()  == 'h2')))

    def close(self):
        self.transport.close()

    def on_write(self, data):
        return self.transport.write(data)

    def on_stream_start(self, i):
        self.payloads[i] = asyncio.StreamReader(loop=self.loop)
        self.pushreqs[i] = Channel(loop=self.loop)

    def on_message_data(self, i, data):
        self.payloads[i].feed_data(data)

    def on_message_end(self, i):
        self.payloads.pop(i).feed_eof()
        self.pushreqs.pop(i).close()
        self.on_stream_start(i)

    def on_stream_end(self, i):
        self.payloads.pop(i).feed_eof()
        self.pushreqs.pop(i).close()

        task = self.handles.pop(i, None)
        if task:
            task.cancel()

        flow = self.flowctl.pop(i, None)
        if flow:
            flow.cancel()

    def on_flow_increase(self, i):
        if not i:
            for flow in self.flowctl.values():
                flow.set_result(None)
            self.flowctl.clear()
        else:
            flow = self.flowctl.pop(i, None)
            if flow:
                flow.set_result(None)

    async def write_all_data(self, i, data, is_final):
        if isinstance(data, Channel):
            async for chunk in data:
                await self.write_all_data(i, chunk, False)
            data = b''  # still need to send an empty END_STREAM frame if is_final = true

        while True:
            sent = self.write_data(i, data, is_final)
            data = data[sent:]
            if not data:
                break
            try:
                # assert (only one coroutine writes to each stream at a time)
                await self.flowctl.setdefault(i, asyncio.Future(loop=self.loop))
            finally:
                flow = self.flowctl.pop(i, None)
                if flow:
                    flow.cancel()


class Client (Connection):
    def __init__(self, loop, authority=None, scheme=None):
        super().__init__(loop, False)
        #: The hostname + port of the peer. If not provided, should be sent
        #: as `:authority` in each request.
        self.authority = authority
        #: The scheme (http/https) used to connect to the peer. Like `authority`,
        #: must be sent as `:scheme` if not set here.
        self.scheme = scheme

    def on_message_push(self, i, parent, method, path, headers):
        self.handles[i] = promise = asyncio.Future(loop=self.loop)
        self.pushreqs[parent].put_nowait(Push(self, i, method, path, headers, promise))

    def on_message_start(self, i, code, method, path, headers):
        payload = self.payloads[i]
        pushreq = self.pushreqs[i]
        self.handles.pop(i).set_result(Response(self, i, code, headers, payload, pushreq))

    async def request(self, method, path, headers=[], data=b'') -> Response:
        head = []
        if self.authority is not None:
            head.append((':authority', self.authority))
        if self.scheme is not None:
            head.append((':scheme', self.scheme))
        head.extend(headers)

        stream = self.next_stream
        while stream in self.handles:  # this http/1.1 connection is busy.
            await asyncio.shield(self.handles[stream], loop=self.loop)
            stream = self.next_stream  # might have switched to http 2 in the meantime

        self.write_message(stream, 0, method, path, head, not data)
        self.handles[stream] = promise = asyncio.Future(loop=self.loop)
        if data:
            await self.write_all_data(stream, data, True)
        try:
            return (await promise)
        except asyncio.CancelledError:
            self.write_reset(stream, raw.CNO_CANCEL)
            raise


class Server (Connection):
    def __init__(self, loop, handle):
        super().__init__(loop, True)
        #: An async function that accepts a single request.
        self.handle = handle

    def on_message_start(self, i, code, method, path, headers):
        if i in self.handles:
            # TODO: actually spawn a task, but make `respond` block until
            #       the previous tasks are completed. Or raise ConnectionError
            #       if there are too many tasks.
            raise NotImplementedError('HTTP/1.1 pipelining not supported (yet)')

        req = Request(self, i, method, path, headers, self.payloads[i])
        self.handles[i] = asyncio.ensure_future(self.handle(req), loop=self.loop)
        self.handles[i].add_done_callback(lambda _: self.handles.pop(i, None))


async def connect(loop, url) -> Client:
    sctx = None
    port = 80

    if isinstance(url, str):
        url = urllib.parse.urlparse(url)

    if url.scheme == 'https':
        if ssl is None:
            raise NotImplementedError('SSL not supported by Python')
        sctx = ssl.create_default_context()
        if ssl.HAS_NPN:
            sctx.set_npn_protocols(['http/1.1', 'h2'])
        if ssl.HAS_ALPN:
            sctx.set_alpn_protocols(['http/1.1', 'h2'])
        port = 443

    proto = Client(loop, authority=url.netloc, scheme=url.scheme)
    await loop.create_connection(lambda: proto, url.hostname, url.port or port, ssl=sctx)
    return proto


async def request(loop, method, url, headers=[], payload=b'') -> Response:
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)

    conn = await connect(loop, url)
    resp = await conn.request(method, url.path, headers, payload)
    return resp
