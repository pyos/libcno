import asyncio

from .raw import Connection


class Bufferable:
    @property
    @asyncio.coroutine
    def payload(self):
        eof = False
        data = b''
        while not eof:
            part, eof = yield from self.fragments.get()
            data += part
        return data


class Request (Bufferable):
    def __init__(self, conn, stream, method, path, headers):
        super().__init__()
        self.connection = conn
        self.stream     = stream
        self.method     = method
        self.path       = path
        self.headers    = headers
        self.fragments  = asyncio.Queue(loop=conn._loop)

    def respond(self, code, headers, data):
        self.connection.write_message(self.stream, code, headers)
        while True:
            try:
                self.connection.write_data(self.stream, data)
            except BlockingIOError:
                yield from self.connection._wait_for_flow_control_update(self.stream)
            else:
                break
        self.connection.write_end(self.stream)


class Response (Bufferable):
    def __init__(self, conn, stream, code, headers):
        self.connection = conn
        self.stream     = stream
        self.code       = code
        self.headers    = headers
        self.fragments  = asyncio.Queue(loop=conn._loop)


class AIOConnection (Connection):
    def __init__(self, *args, loop=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._loop     = loop or asyncio.get_event_loop()
        self._tasks    = {}
        self._readers  = {}
        self._writers  = {}
        self.on_message_start       = self._msg_start
        self.on_message_data        = self._msg_data
        self.on_message_end         = self._msg_end
        self.on_stream_end          = self._msg_abort
        self.on_flow_control_update = self._reopen_flow

    def _msg_start(self, stream, *args):
        pass

    def _msg_data(self, stream, data):
        rd = self._readers.get(stream, None)
        rd and rd.put_nowait((data, False))

    def _msg_end(self, stream, disconnected):
        task = self._tasks.get(stream, None)
        rd = self._readers.pop(stream, None)
        rd and rd.put_nowait((b'', True))
        wr = self._writers.pop(stream, None)
        wr and wr.cancel()
        if task and disconnected and not self.is_client and not task.done():
            return task.set_exception(ConnectionError())

    def _msg_abort(self, stream):
        return self._msg_end(stream, True)

    def _reopen_flow(self, stream):
        if stream == 0:
            for s in self._writers:
                if s != 0:
                    self._reopen_flow(s)
        wr = self._writers.pop(stream, None)
        wr and wr.set_result(True)

    @asyncio.coroutine
    def _wait_for_flow_control_update(self, stream):
        wr = self._writers.get(stream, None)
        if wr:
            wr = self._writers[stream] = asyncio.Future(loop=self._loop)
        return (yield from wr)


class AIOServer (AIOConnection):
    def __init__(self, callback, loop=None):
        super().__init__(client=False, loop=loop)
        self._callback = callback

    def _msg_start(self, stream, *args):
        item = Request(self, stream, *args)
        task = self._tasks[stream] = asyncio.async(self._callback(item, loop=self._loop), loop=self._loop)
        task.add_done_callback(lambda _: (self._tasks.pop(stream, None), self._readers.pop(stream, None)))
        self._readers[stream] = item.fragments


class AIOClient (AIOConnection):
    def __init__(self, http2=True, loop=None):
        super().__init__(http2=http2, loop=loop)
        self._stream = 1
        self._strinc = 2 if http2 else 0

    def _msg_start(self, stream, *args):
        item = Response(self, stream, *args)
        task = self._tasks.get(stream, None)
        task and task.set_result(item)
        self._readers[stream] = item.fragments

    @asyncio.coroutine
    def request(self, method, path, headers, data):
        stream = self._stream

        if stream in self._tasks:
            raise RuntimeError("already waiting for a response on this connection")

        self._stream += self._strinc
        self.write_message(stream, method, path, headers)
        while True:
            try:
                self.write_data(stream, data)
            except BlockingIOError:
                # TODO wait for an increase in flow control window, then retry
                yield from self._wait_for_flow_control_update(stream)
            else:
                break
        self.write_end(stream)

        self._tasks[stream] = fut = asyncio.Future(loop=self._loop)
        try:
            return (yield from fut)
        finally:
            fut.cancel()
            self._tasks.pop(stream, None)
