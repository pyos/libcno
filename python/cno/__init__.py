import asyncio

from .raw import Connection


def _add_content_length(headers, data):
    headers = list(headers)
    for name, value in headers:
        if name.lower() == 'content-length':
            if len(data) != int(value):
                raise ValueError('content-length does not match data length')
            break
    else:
        headers.append(('content-length', str(len(data))))
    return headers


class Request:
    def __init__(self, conn, stream, method, path, headers, data):
        self.conn    = conn
        self.stream  = stream
        self.method  = method
        self.path    = path
        self.headers = headers
        self.data    = data

    def respond(self, code, headers, data):
        self.conn.write_message(self.stream, code, _add_content_length(headers, data))
        self.conn.write_data(self.stream, data)
        self.conn.write_end(self.stream)


class Response:
    def __init__(self, conn, stream, code, headers, data):
        self.conn    = conn
        self.stream  = stream
        self.code    = code
        self.headers = headers
        self.data    = data


class _BufferedConnection (Connection):
    def __init__(self, server, http2):
        super().__init__(server, http2)
        self._on_stream_start  = self.on_stream_start
        self._on_message_start = self.on_message_start
        self._on_message_data  = self.on_message_data
        self._on_message_end   = self.on_message_end
        self._on_stream_end    = self.on_stream_end
        self._streams = {}
        self._client  = not server
        self._http1   = not http2

    def on_stream_start(self, stream):
        self._streams[stream] = None

    def on_stream_end(self, stream):
        self._streams.pop(stream)

    def on_message_start(self, stream, *args):
        self._streams[stream] = list(args) + [b'']

    def on_message_data(self, stream, data):
        self._streams[stream][-1] += data

    def on_message_end(self, stream, disconnect):
        if self._client:
            self.on_message(Response(self, stream, *self._streams[stream]))
        elif not disconnect:
            self.on_message(Request(self, stream, *self._streams[stream]))

    def on_message(self, msg):
        pass


class AIOClient (_BufferedConnection):
    def __init__(self, http2=True, loop=None):
        super().__init__(False, http2)
        self._futures = {}
        self._stream  = 1
        self._strinc  = 2 if http2 else 0
        self._loop = loop

    def on_stream_end(self, stream):
        super().on_stream_end(stream)
        fut = self._futures.pop(stream, None)
        if fut:
            fut.set_exception(ConnectionError())

    @asyncio.coroutine
    def request(self, method, path, headers, data):
        stream = self._stream

        if stream in self._futures:
            raise RuntimeError("already waiting for a response on this connection")

        self._stream += self._strinc
        self.write_message(stream, method, path, _add_content_length(headers, data))
        try:
            self.write_data(stream, data)
        except BlockingIOError:
            # TODO wait for an increase in flow control window, then retry
            raise
        self.write_end(stream)

        self._futures[stream] = fut = asyncio.Future(loop=self._loop)
        try:
            return (yield from fut)
        finally:
            fut.cancel()
            self._futures.pop(stream, None)

    def on_message(self, obj):
        fut = self._futures.pop(obj.stream, None)
        if fut:
            fut.set_result(obj)


class AIOServer (_BufferedConnection):
    def __init__(self, coroutine, loop=None):
        super().__init__(True, True)
        self._loop = loop
        self._coroutine = coroutine

    def on_message(self, obj):
        asyncio.async(self._coroutine(obj, loop=self._loop), loop=self._loop)
