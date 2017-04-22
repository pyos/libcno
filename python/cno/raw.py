from .ffi import ffi
from .ffi.lib import *

try:
    from threading import local as _thread_local
except ImportError:
    class _thread_local: pass  # there's only one thread anyway
_thread_local = _thread_local()


def set_error(t, v, tb):
    _thread_local.err = v.with_traceback(tb)
    return cno_error_set(b'/dev/null', 1, 127, b'Python exception')


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
    m.headers = headers_ref = ffi.new('struct cno_header_t[%s]' % len(headers))
    m.headers_len = len(headers)
    refs = [
        headers_ref,
        pack_string(m.method, method),
        pack_string(m.path,   path)
    ]
    for i, (k, v) in enumerate(headers):
        refs.append(pack_string(m.headers[i].name,  k))
        refs.append(pack_string(m.headers[i].value, v))
    return m, refs


try:
    make_callbacks  # don't recreate the callbacks when reloading this module
except NameError:
    CALLBACKS = {
        'on_write',
        'on_stream_start',
        'on_stream_end',
        'on_flow_increase',
        'on_message_start',
        'on_message_trail',
        'on_message_push',
        'on_message_data',
        'on_message_end',
        'on_frame',
        'on_frame_send',
        'on_pong',
        'on_settings',
    }

    def make_callbacks():
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
    make_callbacks()


class Connection:
    def __init__(self, is_server):
        self._lost       = False
        self._obj        = ffi.new('struct cno_connection_t *')
        self._obj_ref    = ffi.new_handle(self)
        cno_connection_init(self._obj, CNO_SERVER if is_server else CNO_CLIENT)
        self._obj.cb_data = self._obj_ref

        for name in CALLBACKS & set(dir(self)):
            setattr(self._obj, name, globals()[name])

    def __del__(self):
        cno_connection_reset(self._obj)

    def _may_fail(self, ret):
        if ret < 0:
            err = cno_error()
            if err.code != CNO_ERRNO_WOULD_BLOCK:
                self.close()
            if err.code == 127:
                raise _thread_local.err
            else:
                raise ConnectionError(err.code, ffi.string(err.text).decode('utf-8'))
        return ret

    def close(self):
        pass

    @property
    def is_http2(self):
        return cno_connection_is_http2(self._obj)

    @property
    def next_stream(self):
        return cno_connection_next_stream(self._obj)

    def connection_made(self, is_http2):
        return self._may_fail(cno_connection_made(self._obj, CNO_HTTP2 if is_http2 else CNO_HTTP1))

    def connection_lost(self, error=None):
        self._lost = True
        return self._may_fail(cno_connection_lost(self._obj))

    def data_received(self, data):
        return self._may_fail(cno_connection_data_received(self._obj, data, len(data)))

    def write_message(self, i, code, method, path, headers, is_final):
        msg, refs = pack_message(code, method, path, headers)
        return self._may_fail(cno_write_message(self._obj, i, msg, is_final))

    def write_push(self, i, method, path, headers):
        msg, refs = pack_message(0, method, path, headers)
        return self._may_fail(cno_write_push(self._obj, i, msg))

    def write_data(self, i, data, is_final):
        return self._may_fail(cno_write_data(self._obj, i, data, len(data), is_final))

    def write_reset(self, i, code):
        if self._lost:
            return 0
        return self._may_fail(cno_write_reset(self._obj, i, code))
