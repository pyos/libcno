import asyncio

from . import raw


class Channel (asyncio.Queue):
    '''A blocking queue that allows to async-iterate over all pushed items.'''
    EOF = object()

    def eof(self):
        '''Stop the consumer loop. Further attempts to iterate will do nothing.'''
        self.put_nowait(self.EOF)

    async def __aiter__(self):
        return self

    async def __anext__(self):
        it = await self.get()
        if it is self.EOF:
            self.eof()
            raise StopAsyncIteration
        return it


class Request:
    def __init__(self, method: str, path: str, headers: [(str, str)], stream: object):
        super().__init__()
        self.conn     = stream.conn
        self.stream   = stream
        self.method   = method
        self.path     = path
        self.headers  = headers
        self.payload  = Channel()

    async def write_headers(self, code: int, headers: [(str, str)], final: bool):
        '''Begin responding to this request.'''
        self.conn.write_message(self.stream.id, code, "", "", headers, final)

    async def write_data(self, data, final: bool):
        '''Send the next (and possibly the last) chunk of data.'''
        if final and not data:
            self.conn.write_data(self.stream.id, b'', final)

        while data:
            i = self.conn.write_data(self.stream.id, data, final)
            if i:
                data = data[i:]
            if data:
                await self.stream.flow

    async def respond(self, code: int, headers: [(str, str)], data: bytes):
        '''Send a response over the same stream.

            Don't do this on client side. You'll get an exception.

        '''
        if data and self.method != 'HEAD':
            await self.write_headers(code, headers, False)
            await self.write_data(data, True)
        else:
            await self.write_headers(code, headers, False)

    def cancel(self):
        '''Abort the stream. The handling coroutine will most likely be cancelled.'''
        self.conn.write_reset(self.stream.id)

    def push(self, method: str, path: str, headers: [(str, str)]):
        '''Push a request for a resource related to this request.

            The request will be routed through as normal on a new stream.

        '''
        self.conn.write_push(self.stream.id, method, path, headers)


class Response:
    def __init__(self, code: int, headers: [(str, str)], pushed: Channel, stream: object):
        super().__init__()
        self.code    = code
        self.conn    = stream.conn
        self.stream  = stream
        self.headers = headers
        self.pushed  = pushed
        self.payload = Channel()

    def cancel(self):
        '''Abort the stream. This prevents further payload from being received.'''
        self.conn.write_reset(self.stream.id)


class StreamedConnection (raw.Connection):
    '''An asyncio protocol that handles HTTP 1 and 2 connections.

        :param client: whether to run in client mode. [default: True]
        :param force_http2: whether to use HTTP 2 always. [default: False]

        NOTE:: do not use this protocol. Create instances of `Client` and `Server` instead.

        TODO:: choose between HTTP 1 and 2 according to the ALPN handshake by default.

    '''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.streams = {}

    def connection_made(self, transport):
        super().connection_made(transport)
        self.transport = transport

    def on_stream_start(self, i: int):
        self.streams[i] = self.Stream(self, i)

    def on_stream_end(self, i: int):
        self.streams.pop(i).abort()

    def on_message_start(self, i: int, code: int, method: str, path: str, headers: [(str, str)]):
        self.streams[i].message(code, method, path, headers)

    def on_message_data(self, i: int, data: bytes):
        self.streams[i].data(data)

    def on_message_end(self, i: int):
        self.streams[i].end()

    def on_message_push(self, i: int, parent: int, method: str, path: str, headers: [(str, str)]):
        self.streams[parent].push(method, path, headers, self.streams[i])

    def on_flow_increase(self, i: int):
        if i:
            return self.streams[i].open_flow()

        for s in self.streams.values():
            s.open_flow()

    # Other events:
    #   on_frame      (type: int, flags: int, stream: int, payload: bytes)
    #   on_frame_send (type: int, flags: int, stream: int, payload: bytes)


class Client (StreamedConnection):
    '''An asyncio protocol implementing an HTTP 2 client.

        :param loop: an asyncio event loop to run on.

        :param force_http2: whether to default to HTTP 2 instead of HTTP 1.
                            Set this to True if you've already negotiated HTTP 2.
                            Otherwise, send an `Upgrade: h2c` request in HTTP 1 mode
                            first.

        TODO:: implement `Upgrade: h2c`.

    '''
    def __init__(self, loop, force_http2=False):
        super().__init__(force_http2=force_http2)
        self.loop = loop

    async def request(self, method: str, path: str, headers: [(str, str)], data: bytes):
        '''Initiate an HTTP request on a new stream.

            :return: a Response object.

        '''
        stream = self.next_stream
        self.write_message(stream, 0, method, path, headers, not data)

        stream = self.streams[stream]
        while data:
            i = self.write_data(stream.id, data, True)
            if i:
                data = data[i:]
            if data:
                await stream.flow

        return (await stream.resp)

    class Stream:
        def __init__(self, conn, id):
            self.id   = id
            self.conn = conn
            self.flow = asyncio.Future(loop=conn.loop)
            self.resp = asyncio.Future(loop=conn.loop)
            self.rsrc = Channel()
            self.rspo = None

        def open_flow(self):
            self.flow.set_result(None)
            self.flow = asyncio.Future()

        def message(self, code, _1, _2, headers):
            self.rspo = Response(code, headers, self.rsrc, self)
            self.resp.set_result(self.rspo)
            self.data = self.rspo.payload.put_nowait
            self.end  = self.rspo.payload.eof

        def push(self, method, path, headers, stream):
            reqo = Request(method, path, headers, stream)
            reqo.payload.eof()
            self.rsrc.put_nowait((reqo, stream.resp))

        def abort(self):
            self.flow.cancel()
            if self.rspo:
                self.rsrc.eof()
                self.rspo.payload.eof()
            else:
                self.resp.cancel()


class Server (StreamedConnection):
    '''An asyncio protocol implementing an HTTP 2 server.

        :param loop: an asyncio event loop to run on.

        :param handler: an async function to call with each request.
                        The event loop is also passed as the keyword argument `loop`.

    '''
    def __init__(self, loop, handler):
        super().__init__(server=True)
        self.loop    = loop
        self.handler = handler

    class Stream:
        def __init__(self, conn, id):
            self.id   = id
            self.conn = conn
            self.func = conn.handler
            self.flow = asyncio.Future()
            self.reqo = None
            self.task = None

        def open_flow(self):
            self.flow.set_result(None)
            self.flow = asyncio.Future()

        def message(self, _, method, path, headers):
            self.reqo = Request(method, path, headers, self)
            self.task = asyncio.ensure_future(self.func(self.reqo, loop=self.conn.loop))
            self.data = self.reqo.payload.put_nowait
            self.end  = self.reqo.payload.eof

        def abort(self):
            self.flow.cancel()
            if self.task:
                self.task.cancel()
                self.reqo = None
                self.task = None
