import asyncio
import urllib.parse

from collections.abc import AsyncIterable

try:
    import ssl
except ImportError:
    ssl = None

from . import raw


class Channel (asyncio.Queue):
    closed = False

    def close(self):
        self.closed = True
        for g in self._getters:
            if not g.done():
                g.set_exception(StopAsyncIteration())

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
        self._prev_rq = None
        self._this_rq = None

    async def respond(self, code, headers, data):
        if self._prev_rq:
            await self._prev_rq
        if self._this_rq and self._this_rq.done():
            raise ConnectionError('already responded')
        # XXX perhaps imbuing HEAD with a special meaning is a task
        #     for a web framework instead?
        have_data = data and self.method != 'HEAD'
        self.conn.write_message(self.stream, code, '', '', headers, not have_data)
        if have_data:
            await self.conn.write_all_data(self.stream, data, True)
        if self._this_rq:
            self._this_rq.set_result(None)

    def push(self, method, path, headers=[]):
        copy = {':authority', ':scheme'} - {k for k in headers}
        head = [(k, v) for k, v in self.headers if k in copy]
        head.extend(headers)
        self.conn.write_push(self.stream, method, path, head)

    def cancel(self, code=raw.CNO_RST_INTERNAL_ERROR):
        try:
            self.conn.write_reset(self.stream, code)
        except ConnectionError as err:
            if err.errno != raw.CNO_ERRNO_DISCONNECT:
                raise
            self.conn.transport.close()


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
        self._paused  = False

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

    def pause_writing(self):
        self._paused = True

    def resume_writing(self):
        self._paused = False
        self.on_flow_increase(0)

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
        if isinstance(data, AsyncIterable):
            async for chunk in data:
                await self.write_all_data(i, chunk, False)
            data = b''  # still need to send an empty END_STREAM frame if is_final = true

        while True:
            if not self._paused:
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
        self._pipelined = [None]

    def on_message_start(self, i, code, method, path, headers):
        req = Request(self, i, method, path, headers, self.payloads[i])
        handle = self.handles[i] = asyncio.ensure_future(self.handle(req), loop=self.loop)
        handle.add_done_callback(lambda _: self.handles.pop(i, None))

        if not self.is_http2:
            req._this_rq = asyncio.Future(loop=self.loop)
            req._prev_rq = self._pipelined[-1]
            self._pipelined.append(req._this_rq)

            @handle.add_done_callback
            def on_done(_):
                req._this_rq.cancel()
                self._pipelined.remove(req._this_rq)


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
            sctx.set_npn_protocols(['h2', 'http/1.1'])
        if ssl.HAS_ALPN:
            sctx.set_alpn_protocols(['h2', 'http/1.1'])
        port = 443

    proto = Client(loop, authority=url.netloc, scheme=url.scheme)
    await loop.create_connection(lambda: proto, url.hostname, url.port or port, ssl=sctx)
    return proto


async def request(loop, method, url, headers=[], payload=b'') -> Response:
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)

    conn = await connect(loop, url)
    try:
        return await conn.request(method, url.path, headers, payload)
    except BaseException as err:
        conn.close()
        raise
