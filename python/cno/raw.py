from .ffi import CALLBACKS
from ._ffi import ffi
from ._ffi.lib import *

try:
    import threading
except ImportError:
    import dummy_threading as threading


_thread_local = threading.local()


def set_error(t, v, tb):
    _thread_local.err = v.with_traceback(tb)
    return cno_error_set(b'???', 1, 127, '{}: {}'.format(t.__name__, v).encode('utf-8'))


def unpack_string(b):
    return str(ffi.buffer(b.data, b.size), 'utf-8')


def unpack_message(msg):
    return (
        unpack_string(msg.method), unpack_string(msg.path),
        [(unpack_string(msg.headers[i].name),
          unpack_string(msg.headers[i].value)) for i in range(msg.headers_len)]
    )


def pack_string(b, s):
    s = ffi.new('char[]', s.encode('utf-8'))
    b.data = s
    b.size = len(s) - 1  # `s` is null-terminated
    return s  # must be kept alive at least as long as `b`


def pack_message(code, method, path, headers):
    m = ffi.new('struct cno_message_t *')
    m.code = code
    m.headers = ffi.new('struct cno_header_t[%s]' % len(headers))
    m.headers_len = len(headers)
    refs = [
        pack_string(m.method, method),
        pack_string(m.path,   path)
    ]
    for i, (k, v) in enumerate(headers):
        refs.append(pack_string(m.headers[i].name,  k))
        refs.append(pack_string(m.headers[i].value, v))
    return m, refs


for name in CALLBACKS:
    if name == 'on_write':
        def callback(self, data, length):
            ffi.from_handle(self).on_write(ffi.buffer(data, length)[:])
            return 0
    elif name == 'on_message_start':
        def callback(self, stream, msg):
            method, path, headers = unpack_message(msg)
            ffi.from_handle(self).on_message_start(stream, msg.code, method, path, headers)
            return 0
    elif name == 'on_message_push':
        def callback(self, stream, msg, parent):
            method, path, headers = unpack_message(msg)
            ffi.from_handle(self).on_message_push(stream, parent, method, path, headers)
            return 0
    elif name == 'on_message_data':
        def callback(self, stream, data, length):
            ffi.from_handle(self).on_message_data(stream, ffi.buffer(data, length)[:])
            return 0
    elif name == 'on_message_trail':
        def callback(self, stream, msg):
            _, _, headers = unpack_message(msg)
            ffi.from_handle(self).on_message_trail(stream, headers)
            return 0
    else:
        def callback(self, *args, name=name):
            getattr(ffi.from_handle(self), name)(*args)
            return 0
    ffi.def_extern(name, onerror=set_error)(callback)


class Connection:
    def __init__(self, server=False, force_http2=False):
        self.force_http2 = force_http2
        self._obj        = ffi.new('struct cno_connection_t *')
        self._obj_ref    = ffi.new_handle(self)
        cno_connection_init(self._obj, CNO_SERVER if server else CNO_CLIENT)

        self._obj.cb_data = self._obj_ref
        for name in CALLBACKS:
            try:
                getattr(self, name)
                setattr(self._obj, name, globals()[name])
            except AttributeError:
                pass

    def __del__(self):
        cno_connection_reset(self._obj)

    def _may_fail(self, ret):
        if ret < 0:
            cno_connection_reset(self._obj)
            self.transport.close()
            err = cno_error()
            if err.code == 127:
                raise _thread_local.err
            else:
                raise ConnectionError(err.code, ffi.string(err.text).decode('utf-8'))
        return ret

    @property
    def is_http2(self):
        return cno_connection_is_http2(self._obj)

    @property
    def is_client(self):
        return self._obj.client

    @property
    def next_stream(self):
        return cno_stream_next_id(self._obj)

    def connection_made(self, http2=False):
        return self._may_fail(cno_connection_made(self._obj, http2 or self.force_http2))

    def connection_lost(self, exc):
        self._may_fail(cno_connection_lost(self._obj))
        cno_connection_reset(self._obj)

    def data_received(self, data):
        return self._may_fail(cno_connection_data_received(self._obj, data, len(data)))

    def eof_received(self):
        pass

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass

    def write_message(self, i, code, method, path, headers, final):
        msg, refs = pack_message(code, method, path, headers)
        return self._may_fail(cno_write_message(self._obj, i, msg, final))

    def write_push(self, i, method, path, headers):
        msg, refs = pack_message(0, method, path, headers)
        return self._may_fail(cno_write_push(self._obj, i, msg))

    def write_reset(self, i, code):
        return self._may_fail(cno_write_reset(self._obj, i, code))

    def write_data(self, i, data, final):
        return self._may_fail(cno_write_data(self._obj, i, data, len(data), final))
