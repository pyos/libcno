import asyncio

from .raw import Connection


class Stream (asyncio.Queue):
    END = object()

    def send(self, ob):
        return self.put_nowait(ob)

    def eof(self):
        return self.put_nowait(self.END)

    async def __aiter__(self):
        return self

    async def __anext__(self):
        ob = await self.get()
        if ob is self.END:
            self.eof()
            raise StopAsyncIteration
        return ob


class Request:
    def __init__(self, conn, stream, method, path, headers, data, response):
        self.connection = conn
        self.stream     = stream
        self.method     = method
        self.path       = path
        self.headers    = headers
        self.chunks     = data
        self.response   = response

    @property
    async def payload(self):
        data = b''
        async for part in self.chunks:
            data += part
        return data

    async def respond(self, code, headers, data):
        self.connection.write_message(self.stream, code, "", "", headers, not data)
        while data:
            try:
                self.connection.write_data(self.stream, data, True)
            except BlockingIOError:
                await self.connection._wait_for_flow_increase(self.stream)
            else:
                break


class Response:
    def __init__(self, conn, stream, code, headers, data, pushed):
        self.stream  = stream
        self.code    = code
        self.headers = headers
        self.chunks  = data
        self.pushed  = pushed

    @property
    async def payload(self):
        data = b''
        async for part in self.chunks:
            data += part
        return data


class FakeStream:
    def send(self, ob): pass
    def eof(self): pass


class FakeFuture:
    def cancel(self): pass
    def set_result(self, ob): pass


_NO_STREAM = FakeStream()
_NO_TASK   = FakeFuture()


class AIOConnection (Connection):
    def __init__(self, *args, loop=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._loop     = loop or asyncio.get_event_loop()
        self._futures  = {}
        self._readers  = {}
        self._writers  = {}

    def on_message_data(self, stream, data):
        self._readers.get(stream, _NO_STREAM).send(data)

    def on_message_end(self, stream):
        self._readers.pop(stream, _NO_STREAM).eof()

    def on_stream_end(self, stream):
        self._futures.pop(stream, _NO_TASK).cancel()
        self._writers.pop(stream, _NO_TASK).cancel()
        self._readers.pop(stream, _NO_STREAM).eof()

    def on_flow_increase(self, stream):
        if stream:
            self._writers.pop(stream, _NO_TASK).set_result(True)
        else:
            for task in self._writers.values():
                task.set_result(True)
            self._writers.clear()

    async def _wait_for_flow_increase(self, stream):
        wr = self._writers.get(stream, None)
        if wr is None:
            wr = self._writers[stream] = asyncio.Future(loop=self._loop)
        return (await wr)


class AIOServer (AIOConnection):
    def __init__(self, callback, loop=None):
        super().__init__(client=False, loop=loop)
        self._callback = callback

    def on_message_start(self, stream, code, method, path, headers):
        data = self._readers[stream] = Stream(loop=self._loop)
        item = Request(self, stream, method, path, headers, data, None)
        task = self._futures[stream] = asyncio.async(self._callback(item, loop=self._loop), loop=self._loop)
        task.add_done_callback(lambda _: self.on_stream_end(stream))


class AIOClient (AIOConnection):
    def __init__(self, http2=True, loop=None):
        super().__init__(http2=http2, loop=loop)
        self._pushreq = {}

    def on_message_start(self, stream, code, method, path, headers):
        data = self._readers[stream] = Stream(loop=self._loop)
        item = Response(self, stream, code, headers, data, self._pushreq.get(stream))
        self._futures.pop(stream, _NO_TASK).set_result(item)

    def on_stream_end(self, stream):
        super().on_stream_end(stream)
        self._pushreq.pop(stream, _NO_STREAM).eof()

    def on_message_push(self, stream, parent, method, path, headers):
        data = Stream(loop=self._loop)
        data.eof()
        task = self._futures[stream] = asyncio.Future(loop=self._loop)
        item = Request(self, stream, method, path, headers, data, task)
        self._pushreq.get(parent, _NO_STREAM).send(item)

    async def request(self, method, path, headers, data):
        stream = self.next_stream

        if stream in self._futures:
            raise RuntimeError("already waiting for a response on this connection")

        self.write_message(stream, 0, method, path, headers, not data)
        while data:
            try:
                self.write_data(stream, data)
            except BlockingIOError:
                await self._wait_for_flow_increase(stream)
            else:
                break

        self._futures[stream] = fut = asyncio.Future(loop=self._loop)
        self._pushreq[stream] = Stream(loop=self._loop)
        try:
            return (await fut)
        finally:
            fut.cancel()
            self._futures.pop(stream, None)
