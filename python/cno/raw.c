//! file: ../../cno.c
//! file: ../../cno-hpack.c
//! file: ../../cno-common.c
//! file: ../../picohttpparser/picohttpparser.c
//! include_dir: ../..
#ifndef PyModuleDef_NAME
#define PyModuleDef_NAME "raw"
#define PyMODINIT_FUNC_NAME PyInit_raw
#endif

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stddef.h>

#include "cno.h"

#define CNO_ERRNO_PYTHON 65
#define CNO_ERROR_PYTHON CNO_ERROR_SET(CNO_ERRNO_PYTHON, "See Python exception info")


typedef struct {
    PyObject_HEAD
    PyObject *transport;
    cno_connection_t *conn;
} PyCNO;


#define PYCNO_SIMPLE_CALLBACK(...) {                                     \
    PyObject *ret = PyObject_CallMethod((PyObject *) self, __VA_ARGS__); \
    if (ret == NULL) return CNO_ERROR_PYTHON;                            \
    Py_DECREF(ret);                                                      \
    return CNO_OK;                                                       \
}


static PyObject *message_headers(cno_message_t *msg)
{
    PyObject *headers = PyList_New(msg->headers_len);
    size_t i;

    if (headers == NULL) {
        return NULL;
    }

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


static PyObject * pycno_handle_cno_error(PyCNO *self)
{
    int err = cno_error();

    if (err == CNO_ERRNO_PYTHON) {
        return NULL;
    }

    return PyErr_Format(
        err == CNO_ERRNO_NO_MEMORY       ? PyExc_MemoryError :
        err == CNO_ERRNO_ASSERTION       ? PyExc_AssertionError :
        err == CNO_ERRNO_NOT_IMPLEMENTED ? PyExc_NotImplementedError :
        err == CNO_ERRNO_TRANSPORT       ? PyExc_ConnectionError :
        err == CNO_ERRNO_INVALID_STATE   ? PyExc_ConnectionError :
        err == CNO_ERRNO_WOULD_BLOCK     ? PyExc_BlockingIOError :
        PyExc_RuntimeError, "%s (%s:%d)", cno_error_text(), cno_error_file(), cno_error_line());
}


static int pycno_on_write(cno_connection_t *conn, PyCNO *self, const char *data, size_t length)
{
    PyObject *ret = self->transport
        ? PyObject_CallFunction(self->transport, "y#", data, length)
        : PyObject_CallMethod((PyObject *) self, "on_write", "y#", data, length);

    if (ret == NULL) {
        return CNO_ERROR_PYTHON;
    }

    Py_DECREF(ret);
    return CNO_OK;
}


static int pycno_on_stream_start(cno_connection_t *conn, PyCNO *self, size_t stream)
           PYCNO_SIMPLE_CALLBACK("on_stream_start", "n", stream);


static int pycno_on_stream_end(cno_connection_t *conn, PyCNO *self, size_t stream)
           PYCNO_SIMPLE_CALLBACK("on_stream_end", "n", stream);


static int pycno_on_message_start(cno_connection_t *conn, PyCNO *self, size_t stream, cno_message_t *msg)
           PYCNO_SIMPLE_CALLBACK("on_message_start", "nis#s#N", stream, msg->code,
               msg->method.data, msg->method.size, msg->path.data, msg->path.size, message_headers(msg));


static int pycno_on_message_push(cno_connection_t *conn, PyCNO *self, size_t stream, cno_message_t *msg, size_t parent)
           PYCNO_SIMPLE_CALLBACK("on_message_push", "nns#s#N", stream, parent,
               msg->method.data, msg->method.size, msg->path.data, msg->path.size, message_headers(msg));


static int pycno_on_message_data(cno_connection_t *conn, PyCNO *self, size_t stream, const char *data, size_t length)
           PYCNO_SIMPLE_CALLBACK("on_message_data", "ny#", stream, data, length);


static int pycno_on_message_end(cno_connection_t *conn, PyCNO *self, size_t stream)
           PYCNO_SIMPLE_CALLBACK("on_message_end", "n", stream);


static int pycno_on_frame(cno_connection_t *conn, PyCNO *self, cno_frame_t *frame)
           PYCNO_SIMPLE_CALLBACK("on_frame", "nnny#", frame->type, frame->flags,
               frame->stream, frame->payload.data, frame->payload.size);


static int pycno_on_frame_send(cno_connection_t *conn, PyCNO *self, cno_frame_t *frame)
           PYCNO_SIMPLE_CALLBACK("on_frame_send", "nnny#", frame->type, frame->flags,
               frame->stream, frame->payload.data, frame->payload.size);


static int pycno_on_pong(cno_connection_t *conn, PyCNO *self, const char data[8])
           PYCNO_SIMPLE_CALLBACK("on_pong", "y#", data, 8);


static int pycno_on_flow_increase(cno_connection_t *conn, PyCNO *self, size_t stream)
           PYCNO_SIMPLE_CALLBACK("on_flow_increase", "n", stream);


static PyCNO * pycno_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyCNO *self = (PyCNO *) type->tp_alloc(type, 0);

    if (self == NULL) {
        return NULL;
    }

    self->conn = NULL;
    return self;
}


static int pycno_traverse(PyCNO *self, visitproc visit, void *arg)
{
    Py_VISIT(self->transport);
    return 0;
}


static int pycno_clear(PyCNO *self)
{
    Py_XDECREF(self->transport);
    self->transport = NULL;
    return 0;
}


static PyObject * pycno_init(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    int http2  = 1;
    int client = 1;
    char *kwds[] = { "client", "http2", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|pp", kwds, &client, &http2)) {
        return NULL;
    }

    self->conn = cno_connection_new(client ? http2 ? CNO_HTTP2_CLIENT : CNO_HTTP1_CLIENT : CNO_HTTP2_SERVER);

    if (self->conn == NULL) {
        return pycno_handle_cno_error(self);
    }

    self->conn->cb_data = self;
    self->conn->on_write         = &pycno_on_write;
    self->conn->on_stream_start  = &pycno_on_stream_start;
    self->conn->on_stream_end    = &pycno_on_stream_end;
    self->conn->on_message_start = &pycno_on_message_start;
    self->conn->on_message_push  = &pycno_on_message_push;
    self->conn->on_message_data  = &pycno_on_message_data;
    self->conn->on_message_end   = &pycno_on_message_end;
    self->conn->on_frame         = &pycno_on_frame;
    self->conn->on_frame_send    = &pycno_on_frame_send;
    self->conn->on_pong          = &pycno_on_pong;
    self->conn->on_flow_increase = &pycno_on_flow_increase;
    Py_RETURN_NONE;
}


static PyObject * pycno_stub(PyCNO *self, PyObject *args)
{
    Py_RETURN_FALSE;
}


static PyObject * pycno_data_received(PyCNO *self, PyObject *args)
{
    const char *data;
    Py_ssize_t length;

    if (!PyArg_ParseTuple(args, "y#", &data, &length)) {
        return NULL;
    }

    if (cno_connection_data_received(self->conn, data, length)) {
        return pycno_handle_cno_error(self);
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_connection_made(PyCNO *self, PyObject *args)
{
    PyObject *transport;

    if (!PyArg_ParseTuple(args, "O", &transport)) {
        return NULL;
    }

    self->transport = PyObject_GetAttrString(transport, "write");

    if (self->transport == NULL) {
        PyErr_Clear();
    }

    if (cno_connection_made(self->conn)) {
        return pycno_handle_cno_error(self);
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_connection_lost(PyCNO *self, PyObject *args)
{
    if (cno_connection_lost(self->conn)) {
        return pycno_handle_cno_error(self);
    }

    Py_XDECREF(self->transport);
    self->transport = NULL;
    Py_RETURN_NONE;
}


static PyObject * pycno_write_reset(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    Py_ssize_t stream;
    char *kwds[] = { "stream", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "n", kwds, &stream)) {
        return NULL;
    }

    if (cno_write_reset(self->conn, (size_t) stream)) {
        return pycno_handle_cno_error(self);
    }

    Py_RETURN_NONE;
}


static int encode_headers(PyObject *headers, cno_message_t *msg)
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
    msg->headers = PyMem_RawMalloc(sizeof(cno_header_t) * msg->headers_len);
    cno_header_t *header = msg->headers;

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


static PyObject * pycno_write_push(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    cno_message_t msg = { 0 };
    PyObject *headers;
    Py_ssize_t stream;
    char *kwds[] = { "stream", "method", "path", "headers", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ns#s#O", kwds, &stream,
            &msg.method.data, &msg.method.size, &msg.path.data, &msg.path.size, &headers)) {
        return NULL;
    }

    if (encode_headers(headers, &msg)) {
        return NULL;
    }

    if (cno_write_push(self->conn, (size_t) stream, &msg)) {
        PyMem_RawFree(msg.headers);
        return pycno_handle_cno_error(self);
    }

    PyMem_RawFree(msg.headers);
    Py_RETURN_NONE;
}


static PyObject * pycno_write_message(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    cno_message_t msg = { 0 };
    PyObject *headers;
    Py_ssize_t stream;
    int eof = 0;
    char *kwds[] = { "stream", "code", "method", "path", "headers", "eof", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "nis#s#O|p", kwds, &stream, &msg.code,
            &msg.method.data, &msg.method.size, &msg.path.data, &msg.path.size, &headers, &eof)) {
        return NULL;
    }

    if (encode_headers(headers, &msg)) {
        return NULL;
    }

    if (cno_write_message(self->conn, (size_t) stream, &msg, eof)) {
        PyMem_RawFree(msg.headers);
        return pycno_handle_cno_error(self);
    }

    PyMem_RawFree(msg.headers);
    Py_RETURN_NONE;
}


static PyObject * pycno_write_data(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    Py_ssize_t stream;
    Py_ssize_t length;
    const char *data;
    int eof = 0;
    char *kwds[] = { "stream", "data", "eof", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ny#|p", kwds, &stream, &data, &length, &eof)) {
        return NULL;
    }

    if (cno_write_data(self->conn, stream, data, length, eof)) {
        return pycno_handle_cno_error(self);
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_is_client(PyCNO *self, void *closure)
{
    if (self->conn && self->conn->client) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


static PyObject * pycno_next_stream(PyCNO *self, void *closure)
{
    return PyLong_FromLong(cno_stream_next_id(self->conn));
}


static void pycno_dealloc(PyCNO *self)
{
    if (self->conn) {
        cno_connection_destroy(self->conn);
    }

    Py_XDECREF(self->transport);
    Py_TYPE(self)->tp_free(self);
}


static PyMethodDef PyCNOMethods[] = {
    { "eof_received",     (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "pause_writing",    (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "resume_writing",   (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "data_received",    (PyCFunction) pycno_data_received,   METH_VARARGS, NULL },
    { "connection_made",  (PyCFunction) pycno_connection_made, METH_VARARGS, NULL },
    { "connection_lost",  (PyCFunction) pycno_connection_lost, METH_VARARGS, NULL },
    { "write_reset",      (PyCFunction) pycno_write_reset,     METH_VARARGS | METH_KEYWORDS, NULL },
    { "write_push",       (PyCFunction) pycno_write_push,      METH_VARARGS | METH_KEYWORDS, NULL },
    { "write_message",    (PyCFunction) pycno_write_message,   METH_VARARGS | METH_KEYWORDS, NULL },
    { "write_data",       (PyCFunction) pycno_write_data,      METH_VARARGS | METH_KEYWORDS, NULL },

    { "on_write",         (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_stream_start",  (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_stream_end",    (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_flow_increase", (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_message_start", (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_message_push",  (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_message_data",  (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_message_end",   (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_frame",         (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_frame_send",    (PyCFunction) pycno_stub,            METH_VARARGS, NULL },
    { "on_pong",          (PyCFunction) pycno_stub,            METH_VARARGS, NULL },

    { NULL }
};


static PyGetSetDef PyCNOGetSetters[] = {
    { "is_client",   (getter) pycno_is_client,   NULL, NULL, NULL },
    { "next_stream", (getter) pycno_next_stream, NULL, NULL, NULL },
    { NULL }
};


static PyTypeObject PyCNOType = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "cno.Connection",
    .tp_basicsize = sizeof(PyCNO),
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new       = (newfunc)    pycno_new,
    .tp_init      = (initproc)   pycno_init,
    .tp_dealloc   = (destructor) pycno_dealloc,
    .tp_methods   = PyCNOMethods,
    .tp_getset    = PyCNOGetSetters,
    .tp_traverse  = (traverseproc) pycno_traverse,
    .tp_clear     = (inquiry) pycno_clear,
};


static PyModuleDef module = {
    PyModuleDef_HEAD_INIT, PyModuleDef_NAME, NULL, -1, NULL
};


PyMODINIT_FUNC PyMODINIT_FUNC_NAME(void)
{
    PyObject *m = PyModule_Create(&module);

    if (PyType_Ready(&PyCNOType) < 0) {
        return NULL;
    }

    if (m == NULL) {
        return NULL;
    }

    Py_INCREF(&PyCNOType);
    PyModule_AddObject(m, "Connection", (PyObject*) &PyCNOType);
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
