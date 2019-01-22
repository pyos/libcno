from .ffi import ffi, lib
from .ffi.lib import *

try:
    from threading import local as _thread_local
except ImportError:
    class _thread_local: pass  # there's only one thread anyway
_thread_local = _thread_local()


def _str(b):
    '''struct cno_buffer_t -> str'''
    return str(ffi.buffer(b.data, b.size), 'utf-8')


def _tail(t):
    '''struct cno_tail_t -> [(str, str)]'''
    return [(_str(h.name), _str(h.value)) for h in t.headers[0:t.headers_len]]


def _msg(m):
    '''struct cno_message_t -> (str, str, [(str, str)])'''
    return _str(m.method), _str(m.path), _tail(m)


def _buf(b, s):
    '''struct cno_message_t, str -> ffi.cdata'''
    b.data = ref = ffi.from_buffer(s.encode('utf-8'))
    b.size = len(ref)
    return ref  # must outlive `b`


def _msgpack(code, method, path, headers):
    '''(int, str, str, [(str, str)]) -> (struct cno_message_t, [ffi.cdata])'''
    m = ffi.new('struct cno_message_t *')
    m.code = code
    m.headers = ref = ffi.new('struct cno_header_t[%s]' % len(headers))
    m.headers_len = len(headers)
    refs = [ref, _buf(m.method, method), _buf(m.path, path)]
    for h, (k, v) in zip(m.headers[0:m.headers_len], headers):
        refs.append(_buf(h.name, k.lower()))
        refs.append(_buf(h.value, v))
    return m, refs


try:
    _CALLBACKS  # don't recreate the callbacks when reloading this module
except NameError:
    _CALLBACKS = {
        'on_writev':        lambda self, iov, cnt: self.on_writev([ffi.unpack(iov[i].data, iov[i].size) for i in range(cnt) if iov[i].size]),
        'on_close':         lambda self: self.on_close(),
        'on_stream_start':  lambda self, id: self.on_stream_start(id),
        'on_stream_end':    lambda self, id, code, side: self.on_stream_end(id, code, side),
        'on_flow_increase': lambda self, id: self.on_flow_increase(id),
        'on_message_head':  lambda self, id, m: self.on_message_head(id, m.code, *_msg(m)),
        'on_message_tail':  lambda self, id, t: self.on_message_tail(id, _tail(t) if t else None),
        'on_message_push':  lambda self, id, m, parent: self.on_message_push(id, parent, *_msg(m)),
        'on_message_data':  lambda self, id, data, size: self.on_message_data(id, ffi.unpack(data, size)),
        'on_frame':         lambda self, frame: self.on_frame(frame),
        'on_frame_send':    lambda self, frame: self.on_frame_send(frame),
        'on_pong':          lambda self, data: self.on_pong(ffi.unpack(data, 8)),
        'on_settings':      lambda self: self.on_settings(),
        'on_upgrade':       lambda self, id: self.on_upgrade(id),
    }

    def _make_callbacks():
        def _except(t, v, tb):
            _thread_local.err = v.with_traceback(tb)
            return cno_error_set(127, b'Python exception')

        for name, f in _CALLBACKS.items():
            @ffi.def_extern(name, onerror=_except)
            def _(self, *args, f=f):
                f(ffi.from_handle(self), *args)
                return 0
    _make_callbacks()


class Connection:
    def __init__(self, server):
        self.__c = ffi.new('struct cno_connection_t *')
        self.__p = ffi.new_handle(self)
        cno_init(self.__c, CNO_SERVER if server else CNO_CLIENT)
        self.__c.cb_code = self.__make_vtable()
        self.__c.cb_data = self.__p

    def __del__(self):
        if hasattr(self, '__c'):
            cno_fini(self.__c)

    @classmethod
    def __make_vtable(cls):
        try:
            return cls.__vtable
        except AttributeError:
            cls.__vtable = ffi.new('struct cno_vtable_t *')
            for name in _CALLBACKS:
                if hasattr(cls, name):
                    setattr(cls.__vtable, name, getattr(lib, name))
            return cls.__vtable

    def __throw(self, ret):
        if ret < 0:
            err = cno_error()
            if err.code != CNO_ERRNO_WOULD_BLOCK:
                self.close()
            raise _thread_local.err if err.code == 127 else ConnectionError(err.code, ffi.string(err.text).decode('utf-8'))
        return ret

    def close(self):
        pass

    @property
    def is_http2(self):
        return self.__c.mode == CNO_HTTP2

    @property
    def next_stream(self):
        return cno_next_stream(self.__c)

    def connection_made(self, is_http2):
        self.__throw(cno_begin(self.__c, CNO_HTTP2 if is_http2 else CNO_HTTP1))

    def connection_lost(self, error=None):
        self.__throw(cno_eof(self.__c))

    def data_received(self, data):
        self.__throw(cno_consume(self.__c, data, len(data)))

    def write_head(self, i, code, method, path, headers, is_final):
        msg, refs = _msgpack(code, method, path, headers)
        self.__throw(cno_write_head(self.__c, i, msg, is_final))

    def write_push(self, i, method, path, headers):
        msg, refs = _msgpack(0, method, path, headers)
        self.__throw(cno_write_push(self.__c, i, msg))

    def write_data(self, i, data, is_final):
        return self.__throw(cno_write_data(self.__c, i, ffi.from_buffer(data), len(data), is_final))

    def write_reset(self, i, code):
        self.__throw(cno_write_reset(self.__c, i, code))

    def write_ping(self, data):
        assert len(data) == 8
        self.__throw(cno_write_ping(self.__c, ffi.from_buffer(data)))

    def write_message(self, *args):
        return self.write_head(*args)
