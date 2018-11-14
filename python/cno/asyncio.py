import socket
import asyncio
import urllib.parse
import collections.abc

try:
    import ssl
    try:
        import certifi
    except ImportError:
        certifi = None
except ImportError:
    ssl = None

from . import raw


class Channel (collections.abc.AsyncIterator, asyncio.Queue):
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
        await self.conn.write_head_blocking(lambda: self.stream, code, '', '', headers, not have_data)
        if have_data:
            await self.conn.write_all_data(self.stream, data)

    def push(self, method, path, headers=[]):
        copy = {':authority', ':scheme'} - {k for k, _ in headers}
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
        self._promise = promise

    @property
    async def response(self):
        return (await asyncio.shield(self._promise, loop=self.conn.loop))

    def cancel(self, code=raw.CNO_RST_CANCEL):
        self.conn.write_reset(self.stream, code)


def _cancel_and_ignore(task):
    task.cancel()
    task.add_done_callback(lambda t: t.exception())


class Connection (raw.Connection, asyncio.Protocol):
    def __init__(self, loop, server, force_http2=False):
        super().__init__(server)
        self.loop = loop
        self._data = {} # stream id -> asyncio.StreamReader for current message body
        self._push = {} # stream id -> Channel for push requests
        self._coro = {} # stream id -> handling task (server) or response future (client)
        self._flow = {} # stream id -> flow control future
        self._stop = False
        self._force_h2 = force_http2
        self._stream_end = asyncio.Event(loop=loop)

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        sctx = transport.get_extra_info('ssl_object')
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        h2a = sctx and ssl.HAS_ALPN and sctx.selected_alpn_protocol() == 'h2'
        h2n = sctx and ssl.HAS_NPN  and sctx.selected_npn_protocol()  == 'h2'
        super().connection_made(self._force_h2 or h2a or h2n)

    def connection_lost(self, exc):
        self._stream_end.set() # wake all, forcing a DISCONNECT error
        return super().connection_lost(exc)

    def close(self):
        self.transport.close()

    def on_writev(self, chunks):
        self.transport.write(b''.join(chunks))

    def on_close(self):
        self.transport.close()

    def on_stream_start(self, i):
        self._data[i] = asyncio.StreamReader(loop=self.loop)
        self._push[i] = Channel(loop=self.loop)

    def on_message_data(self, i, data):
        self._data[i].feed_data(data)

    def on_message_tail(self, i, trailers):
        self._data.pop(i).feed_eof()
        self._push.pop(i).close()

    def on_stream_end(self, i):
        data = self._data.pop(i, None)
        push = self._push.pop(i, None)
        task = self._coro.pop(i, None)
        flow = self._flow.pop(i, None)
        data and data.feed_eof()
        push and push.close()
        task and _cancel_and_ignore(task)
        flow and flow.cancel()
        self._stream_end.set()
        self._stream_end.clear()

    def pause_writing(self):
        self._stop = True

    def resume_writing(self):
        self._stop = False
        self.on_flow_increase(0)

    def on_flow_increase(self, i):
        if i == 0:
            for flow in self._flow.values():
                flow.set_result(None)
            self._flow.clear()
        elif i in self._flow:
            self._flow.pop(i).set_result(None)

    async def write_head_blocking(self, stream_fn, code, method, path, head, final):
        while True:
            stream = stream_fn()
            try:
                self.write_head(stream, code, method, path, head, final)
                return stream
            except ConnectionError as e:
                if e.errno != raw.CNO_ERRNO_WOULD_BLOCK:
                    raise
                await self._stream_end.wait()

    async def write_all_data(self, i, data, final=True):
        if isinstance(data, collections.abc.AsyncIterable):
            async for chunk in data:
                await self.write_all_data(i, chunk, False)
            return self.write_data(i, b'', True)
        view = memoryview(data)
        while True:
            if not self._stop:
                view = view[self.write_data(i, view, final):]
                if not view:
                    break
            try:
                await self._flow.setdefault(i, asyncio.Future(loop=self.loop))
            finally:
                self._flow.pop(i, None)


class Client (Connection):
    def __init__(self, loop, authority=None, scheme=None, **kwargs):
        super().__init__(loop, False, **kwargs)
        #: The hostname + port of the peer. If not provided, should be sent as `:authority` in each request.
        self.authority = authority
        #: The scheme (http/https) used to connect to the peer. Must be sent as `:scheme` if not set here.
        self.scheme = scheme

    def on_message_push(self, i, parent, method, path, headers):
        self._coro[i] = asyncio.Future(loop=self.loop)
        self._push[parent].put_nowait(Push(self, i, method, path, headers, self._coro[i]))

    def on_message_head(self, i, code, method, path, headers):
        self._coro.pop(i).set_result(Response(self, i, code, headers, self._data[i], self._push[i]))

    async def request(self, method, path, headers=[], data=b'') -> Response:
        head = []
        if self.authority is not None:
            head.append((':authority', self.authority))
        if self.scheme is not None:
            head.append((':scheme', self.scheme))
        head.extend(headers)

        stream = await self.write_head_blocking(lambda: self.next_stream, 0, method, path, head, not data)
        self._coro[stream] = f = asyncio.Future(loop=self.loop)
        try:
            if data:
                await self.write_all_data(stream, data)
            return (await f)
        except asyncio.CancelledError:
            self.write_reset(stream, raw.CNO_RST_CANCEL)
            raise


class Server (Connection):
    def __init__(self, loop, handle):
        super().__init__(loop, True)
        self._func = handle
        self._prev = None
        self._have_buffered_data = False

    def data_received(self, data):
        self._have_buffered_data = False
        try:
            return super().data_received(data)
        except ConnectionError as e:
            if e.errno != raw.CNO_ERRNO_WOULD_BLOCK:
                raise
            self._have_buffered_data = True

    def on_stream_end(self, i):
        super().on_stream_end(i)
        if self._have_buffered_data:
            self.data_received(b'')

    def on_message_head(self, i, code, method, path, headers):
        req = Request(self, i, method, path, headers, self._data[i])
        fut = self._coro[i] = asyncio.ensure_future(self._func(req), loop=self.loop)


async def connect(loop, url, ssl_ctx=None, ssl_hostname=None, **kwargs) -> Client:
    port = 80
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)
    if url.scheme == 'https':
        if ssl is None:
            raise NotImplementedError('SSL not supported by Python')
        if ssl_ctx is None:
            ssl_ctx = ssl.create_default_context(capath=None if certifi is None else certifi.where())
        if ssl.HAS_NPN:
            ssl_ctx.set_npn_protocols(['h2', 'http/1.1'])
        if ssl.HAS_ALPN:
            ssl_ctx.set_alpn_protocols(['h2', 'http/1.1'])
        port = 443
    else:
        ssl_ctx = None
    proto = Client(loop, authority=url.netloc, scheme=url.scheme, **kwargs)
    await loop.create_connection(lambda: proto, url.hostname, url.port or port, ssl=ssl_ctx, server_hostname=ssl_hostname)
    return proto


async def request(loop, method, url, headers=[], data=b'', **kwargs) -> Response:
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)
    conn = await connect(loop, url, **kwargs)
    try:
        return await conn.request(method, url.path, headers, data)
    except:
        conn.close()
        raise
