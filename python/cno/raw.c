//! library: cno
//! library_dir: ../../obj
//! include_dir: ../..
#ifndef PyModuleDef_NAME
#define PyModuleDef_NAME "raw"
#define PyMODINIT_FUNC_NAME PyInit_raw
#endif

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cno/core.h>


enum
{
    CNO_ERRNO_PYTHON = 64,
};



struct connection_obj_t
{
    PyObject_HEAD
    PyObject *transport;
    int initialized;
    int force_http2;
    struct cno_connection_t conn;
};


static PyObject * py_handle_error(struct connection_obj_t *self)
{
    if (self->transport) {
        PyObject *ob = PyObject_CallMethod(self->transport, "close", "");
        Py_XDECREF(ob);
        Py_DECREF(self->transport);
        self->transport = NULL;
    }

    const struct cno_error_t *err = cno_error();

    if (err->code == CNO_ERRNO_PYTHON)
        return NULL;

    return PyErr_Format(
        err->code == CNO_ERRNO_NO_MEMORY       ? PyExc_MemoryError
      : err->code == CNO_ERRNO_ASSERTION       ? PyExc_AssertionError
      : err->code == CNO_ERRNO_NOT_IMPLEMENTED ? PyExc_NotImplementedError
      : err->code == CNO_ERRNO_WOULD_BLOCK     ? PyExc_BlockingIOError
      : PyExc_ConnectionError, "%s", err->text);
}


static int py_on_write(void *self, const char *data, size_t length)
{
    struct connection_obj_t *__s = self;

    if (__s->transport == NULL)
        return CNO_OK;

    PyObject *ret = PyObject_CallMethod(__s->transport, "write", "y#", data, length);

    if (ret == NULL)
        return CNO_ERROR(PYTHON, "Python exception");

    Py_DECREF(ret);
    return CNO_OK;
}


#define PY_SIMPLE_CALLBACK(m, ...) {                         \
    PyObject *f = PyObject_GetAttrString(self, m);           \
    if (f == NULL) {                                         \
        PyErr_Clear();                                       \
        return CNO_OK;                                       \
    }                                                        \
    PyObject *ret = PyObject_CallFunction(f, __VA_ARGS__);   \
    if (ret == NULL)                                         \
        return CNO_ERROR(PYTHON, "Python exception");        \
    Py_DECREF(ret);                                          \
    return CNO_OK;                                           \
}


static PyObject *py_headers_of(const struct cno_message_t *msg)
{
    PyObject *headers = PyList_New(msg->headers_len);

    if (headers == NULL)
        return NULL;

    size_t i;
    for (i = 0; i < msg->headers_len; ++i) {
        PyObject *header = Py_BuildValue("(s#s#)",
            msg->headers[i].name.data,  msg->headers[i].name.size,
            msg->headers[i].value.data, msg->headers[i].value.size);

        if (header == NULL) {
            Py_DECREF(headers);
            return NULL;
        }

        PyList_SET_ITEM(headers, i, header);
    }

    return headers;
}


static int py_on_stream_start(void *self, size_t stream)
           PY_SIMPLE_CALLBACK("on_stream_start", "n", stream);


static int py_on_stream_end(void *self, size_t stream)
           PY_SIMPLE_CALLBACK("on_stream_end", "n", stream);


static int py_on_message_start(void *self, size_t stream, const struct cno_message_t *msg)
           PY_SIMPLE_CALLBACK("on_message_start", "nis#s#N", stream, msg->code,
               msg->method.data, msg->method.size, msg->path.data, msg->path.size, py_headers_of(msg));


static int py_on_message_push(void *self, size_t stream, const struct cno_message_t *msg, size_t parent)
           PY_SIMPLE_CALLBACK("on_message_push", "nns#s#N", stream, parent,
               msg->method.data, msg->method.size, msg->path.data, msg->path.size, py_headers_of(msg));


static int py_on_message_data(void *self, size_t stream, const char *data, size_t length)
           PY_SIMPLE_CALLBACK("on_message_data", "ny#", stream, data, length);


static int py_on_message_end(void *self, size_t stream)
           PY_SIMPLE_CALLBACK("on_message_end", "n", stream);


static int py_on_frame(void *self, const struct cno_frame_t *frame)
           PY_SIMPLE_CALLBACK("on_frame", "nnny#", frame->type, frame->flags,
               frame->stream, frame->payload.data, frame->payload.size);


static int py_on_frame_send(void *self, const struct cno_frame_t *frame)
           PY_SIMPLE_CALLBACK("on_frame_send", "nnny#", frame->type, frame->flags,
               frame->stream, frame->payload.data, frame->payload.size);


static int py_on_pong(void *self, const char *data)
           PY_SIMPLE_CALLBACK("on_pong", "y#", data, 8);


static int py_on_flow_increase(void *self, size_t stream)
           PY_SIMPLE_CALLBACK("on_flow_increase", "n", stream);


static int py_init(struct connection_obj_t *self, PyObject *args, PyObject *kwargs)
{
    int server = 0;
    int force_http2 = 0;
    char *kwds[] = { "server", "force_http2", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|pp", kwds, &server, &force_http2))
        return -1;

    if (server && force_http2)
        return PyErr_Format(PyExc_ValueError, "servers choose HTTP version automatically"), -1;

    cno_connection_init(&self->conn, server ? CNO_SERVER : CNO_CLIENT);
    self->conn.cb_data = self;
    self->conn.on_write         = &py_on_write;
    self->conn.on_stream_start  = &py_on_stream_start;
    self->conn.on_stream_end    = &py_on_stream_end;
    self->conn.on_message_start = &py_on_message_start;
    self->conn.on_message_push  = &py_on_message_push;
    self->conn.on_message_data  = &py_on_message_data;
    self->conn.on_message_end   = &py_on_message_end;
    self->conn.on_frame         = &py_on_frame;
    self->conn.on_frame_send    = &py_on_frame_send;
    self->conn.on_pong          = &py_on_pong;
    self->conn.on_flow_increase = &py_on_flow_increase;
    self->force_http2 = force_http2;
    self->initialized = 1;
    return 0;
}


static int py_traverse(struct connection_obj_t *self, visitproc visit, void *arg)
{
    Py_VISIT(self->transport);
    return 0;
}


static int py_clear(struct connection_obj_t *self)
{
    Py_XDECREF(self->transport);
    return 0;
}


static PyObject * py_nop(struct connection_obj_t *self, PyObject *args)
{
    Py_RETURN_NONE;
}


static PyObject * py_data_received(struct connection_obj_t *self, PyObject *args)
{
    const char *data;
    Py_ssize_t length;

    if (!PyArg_ParseTuple(args, "y#", &data, &length))
        return NULL;

    if (cno_connection_data_received(&self->conn, data, length))
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static PyObject * py_connection_made(struct connection_obj_t *self, PyObject *args)
{
    PyObject *transport;

    if (!PyArg_ParseTuple(args, "O", &transport))
        return NULL;

    Py_INCREF(transport);
    self->transport = transport;

    // TODO use ALPN/NPN (asyncio does not provide them through get_extra_data yet.)
    if (cno_connection_made(&self->conn, self->force_http2 ? CNO_HTTP2 : CNO_HTTP1))
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static PyObject * py_connection_lost(struct connection_obj_t *self, PyObject *args)
{
    Py_XDECREF(self->transport);
    self->transport = NULL;

    if (cno_connection_lost(&self->conn))
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static PyObject * py_write_reset(struct connection_obj_t *self, PyObject *args)
{
    Py_ssize_t stream;

    if (!PyArg_ParseTuple(args, "n", &stream))
        return NULL;

    if (cno_write_reset(&self->conn, (size_t) stream))
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static int encode_headers(PyObject *headers, struct cno_message_t *msg)
{
    Py_ssize_t len = PySequence_Size(headers);

    if (len == -1) {
        PyErr_Format(PyExc_TypeError, "headers must be a sequence, not %s", Py_TYPE(headers)->tp_name);
        return -1;
    }

    PyObject *iter = PyObject_GetIter(headers);
    PyObject *item;

    if (iter == NULL) {
        return -1;
    }

    msg->headers_len = (size_t) len;
    msg->headers = PyMem_RawMalloc(sizeof(struct cno_header_t) * msg->headers_len);
    struct cno_header_t *header = msg->headers;

    if (msg->headers == NULL) {
        Py_DECREF(iter);
        PyErr_NoMemory();
        return -1;
    }

    while ((item = PyIter_Next(iter))) {
        if (!PyArg_ParseTuple(item, "s#s#", &header->name.data,  &header->name.size,
                                            &header->value.data, &header->value.size)) {
            Py_DECREF(item);
            Py_DECREF(iter);
            PyMem_RawFree(msg->headers);
            PyErr_Format(PyExc_ValueError, "headers must be 2-tuples of strings");
            return -1;
        }

        Py_DECREF(item);
        ++header;
    }

    Py_DECREF(iter);

    if (PyErr_Occurred()) {
        PyMem_RawFree(msg->headers);
        return -1;
    }

    return 0;
}


static PyObject * py_write_push(struct connection_obj_t *self, PyObject *args)
{
    struct cno_message_t msg = { 0 };
    PyObject *headers;
    Py_ssize_t stream;

    if (!PyArg_ParseTuple(args, "ns#s#O", &stream,
            &msg.method.data, &msg.method.size, &msg.path.data, &msg.path.size, &headers))
        return NULL;

    if (encode_headers(headers, &msg))
        return NULL;

    int failed = cno_write_push(&self->conn, (size_t) stream, &msg);
    PyMem_RawFree(msg.headers);

    if (failed)
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static PyObject * py_write_message(struct connection_obj_t *self, PyObject *args)
{
    struct cno_message_t msg = { 0 };
    PyObject *headers;
    Py_ssize_t stream;
    int eof = 0;

    if (!PyArg_ParseTuple(args, "nis#s#O|p", &stream, &msg.code,
            &msg.method.data, &msg.method.size, &msg.path.data, &msg.path.size, &headers, &eof))
        return NULL;

    if (encode_headers(headers, &msg))
        return NULL;

    int failed = cno_write_message(&self->conn, (size_t) stream, &msg, eof);
    PyMem_RawFree(msg.headers);

    if (failed)
        return py_handle_error(self);

    Py_RETURN_NONE;
}


static PyObject * py_write_data(struct connection_obj_t *self, PyObject *args)
{
    Py_ssize_t stream;
    Py_ssize_t length;
    const char *data;
    int eof = 0;

    if (!PyArg_ParseTuple(args, "ny#|p", &stream, &data, &length, &eof))
        return NULL;

    ssize_t i = cno_write_data(&self->conn, stream, data, length, eof);

    if (i < 0)
        return py_handle_error(self);

    return PyLong_FromSsize_t(i);
}


static PyObject * py_is_client(struct connection_obj_t *self, void *closure)
{
    if (self->conn.client)
        Py_RETURN_TRUE;

    Py_RETURN_FALSE;
}


static PyObject * py_is_http2(struct connection_obj_t *self, void *closure)
{
    if (cno_connection_is_http2(&self->conn))
        Py_RETURN_TRUE;

    Py_RETURN_FALSE;
}


static PyObject * py_next_stream(struct connection_obj_t *self, void *closure)
{
    return PyLong_FromLong(cno_stream_next_id(&self->conn));
}


static void py_dealloc(struct connection_obj_t *self)
{
    if (self->initialized)
        cno_connection_reset(&self->conn);

    Py_XDECREF(self->transport);
    Py_TYPE(self)->tp_free(self);
}


static PyMethodDef ConnectionMethods[] = {
    { "connection_made",  (PyCFunction) py_connection_made, METH_VARARGS, NULL },
    { "connection_lost",  (PyCFunction) py_connection_lost, METH_VARARGS, NULL },
    { "data_received",    (PyCFunction) py_data_received,   METH_VARARGS, NULL },
    { "eof_received",     (PyCFunction) py_nop,             METH_VARARGS, NULL },
    { "pause_writing",    (PyCFunction) py_nop,             METH_VARARGS, NULL },
    { "resume_writing",   (PyCFunction) py_nop,             METH_VARARGS, NULL },
    { "write_reset",      (PyCFunction) py_write_reset,     METH_VARARGS, NULL },
    { "write_push",       (PyCFunction) py_write_push,      METH_VARARGS, NULL },
    { "write_message",    (PyCFunction) py_write_message,   METH_VARARGS, NULL },
    { "write_data",       (PyCFunction) py_write_data,      METH_VARARGS, NULL },
    { NULL }
};


static PyGetSetDef ConnectionGetSetters[] = {
    { "is_client",   (getter) py_is_client,   NULL, NULL, NULL },
    { "is_http2",    (getter) py_is_http2,    NULL, NULL, NULL },
    { "next_stream", (getter) py_next_stream, NULL, NULL, NULL },
    { NULL }
};


static PyTypeObject ConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "cno.Connection",
    .tp_basicsize = sizeof(struct connection_obj_t),
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new       = PyType_GenericNew,
    .tp_init      = (initproc)     py_init,
    .tp_dealloc   = (destructor)   py_dealloc,
    .tp_traverse  = (traverseproc) py_traverse,
    .tp_clear     = (inquiry)      py_clear,
    .tp_methods   = ConnectionMethods,
    .tp_getset    = ConnectionGetSetters,
};


static PyModuleDef module = { PyModuleDef_HEAD_INIT, PyModuleDef_NAME, NULL, -1, NULL };


PyMODINIT_FUNC PyMODINIT_FUNC_NAME(void)
{
    if (PyType_Ready(&ConnectionType) < 0)
        return NULL;

    PyObject *m = PyModule_Create(&module);

    if (m == NULL)
        return NULL;

    Py_INCREF(&ConnectionType);
    PyModule_AddObject(m, "Connection", (PyObject *) &ConnectionType);
    PyModule_AddIntMacro(m, CNO_FRAME_DATA);
    PyModule_AddIntMacro(m, CNO_FRAME_HEADERS);
    PyModule_AddIntMacro(m, CNO_FRAME_PRIORITY);
    PyModule_AddIntMacro(m, CNO_FRAME_RST_STREAM);
    PyModule_AddIntMacro(m, CNO_FRAME_SETTINGS);
    PyModule_AddIntMacro(m, CNO_FRAME_PUSH_PROMISE);
    PyModule_AddIntMacro(m, CNO_FRAME_PING);
    PyModule_AddIntMacro(m, CNO_FRAME_GOAWAY);
    PyModule_AddIntMacro(m, CNO_FRAME_WINDOW_UPDATE);
    PyModule_AddIntMacro(m, CNO_FRAME_CONTINUATION);
    PyModule_AddIntMacro(m, CNO_FLAG_ACK);
    PyModule_AddIntMacro(m, CNO_FLAG_END_STREAM);
    PyModule_AddIntMacro(m, CNO_FLAG_END_HEADERS);
    PyModule_AddIntMacro(m, CNO_FLAG_PADDED);
    PyModule_AddIntMacro(m, CNO_FLAG_PRIORITY);
    return m;
}
