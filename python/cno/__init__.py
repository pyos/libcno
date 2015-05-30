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
        self.connection.write_message(self.stream, code, headers, not data)
        while data:
            try:
                self.connection.write_data(self.stream, data, True)
            except BlockingIOError:
                yield from self.connection._wait_for_flow_control_update(self.stream)
            else:
                break


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

    def connection_lost(self, exc):
        super().connection_lost(exc)
        for task in self._tasks.values():
            if not task.done():
                task.cancel()

    def _msg_data(self, stream, data):
        rd = self._readers.get(stream, None)
        rd and rd.put_nowait((data, False))

    def _msg_end(self, stream, disconnected):
        rd = self._readers.pop(stream, None)
        rd and rd.put_nowait((b'', True))
        if disconnected:
            wr = self._writers.pop(stream, None)
            wr and wr.cancel()
            task = self._tasks.pop(stream, None)
            if task and not task.done():
                return task.cancel()

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
        if not wr:
            wr = self._writers[stream] = asyncio.Future(loop=self._loop)
        return (yield from wr)


class AIOServer (AIOConnection):
    def __init__(self, callback, loop=None):
        super().__init__(client=False, loop=loop)
        self._callback = callback

    def _msg_start(self, stream, method, path, headers):
        item = Request(self, stream, method, path, headers)
        task = self._tasks[stream] = asyncio.async(self._callback(item, loop=self._loop), loop=self._loop)
        task.add_done_callback(lambda _: (self._tasks.pop(stream, None), self._readers.pop(stream, None)))
        self._readers[stream] = item.fragments


class AIOClient (AIOConnection):
    def __init__(self, http2=True, loop=None):
        super().__init__(http2=http2, loop=loop)

    def _msg_start(self, stream, code, headers):
        item = Response(self, stream, code, headers)
        task = self._tasks.pop(stream, None)
        task and task.set_result(item)
        self._readers[stream] = item.fragments

    @asyncio.coroutine
    def request(self, method, path, headers, data):
        stream = self.next_stream

        if stream in self._tasks:
            raise RuntimeError("already waiting for a response on this connection")

        self.write_message(stream, method, path, headers, not data)
        while data:
            try:
                self.write_data(stream, data)
            except BlockingIOError:
                yield from self._wait_for_flow_control_update(stream)
            else:
                break

        self._tasks[stream] = fut = asyncio.Future(loop=self._loop)
        try:
            return (yield from fut)
        finally:
            fut.cancel()
            self._tasks.pop(stream, None)
