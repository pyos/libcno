//! file: ../src/core.c
//! file: ../src/iovec.c
//! file: ../src/error.c
//! file: ../src/write.c
//! file: ../picohttpparser/picohttpparser.c
//! include_dir: ..
//! include_dir: ../include
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include "core.h"
#include "error.h"
#include "write.h"


typedef struct
{
    PyObject_HEAD
    cno_connection_t *conn;
    PyObject *on_write;
    PyObject *on_message_start;
    PyObject *on_message_data;
    PyObject *on_message_end;
    PyObject *transport;
} PyCNO;


static PyObject * pycno_handle_cno_error(PyCNO *self)
{
    // TODO use different exception types
    return PyErr_Format(PyExc_RuntimeError, "%d: %s (%s:%d)",
        cno_error(), cno_error_text(), cno_error_file(), cno_error_line());
}


static void pycno_on_message_start(cno_connection_t *conn, PyCNO *self, size_t stream, cno_message_t *msg)
{
    if (PyErr_Occurred()) {
        return;
    }

    if (self->on_message_start) {
        PyObject *headers = PyList_New(msg->headers_len);
        size_t i;

        if (headers == NULL) {
            return;
        }

        for (i = 0; i < msg->headers_len; ++i) {
            PyObject *header = Py_BuildValue("(s#s#)",
                msg->headers[i].name.data,  msg->headers[i].name.size,
                msg->headers[i].value.data, msg->headers[i].value.size);

            if (header == NULL) {
                Py_DECREF(headers);
                return;
            }

            PyList_SET_ITEM(headers, i, header);
        }

        PyObject *ret = PyObject_CallFunction(
          self->on_message_start, "n(ii)is#s#N", stream,
            msg->major, msg->minor, msg->code,
            msg->method.data, msg->method.size,
            msg->path.data,   msg->path.size, headers);
        Py_XDECREF(ret);
    }
}


static void pycno_on_message_data(cno_connection_t *conn, PyCNO *self, size_t stream, const char *data, size_t length)
{
    if (PyErr_Occurred()) {
        return;
    }

    if (self->on_message_data) {
        PyObject *ret = PyObject_CallFunction(self->on_message_data, "ny#", stream, data, length);
        Py_XDECREF(ret);
    }
}


static void pycno_on_message_end(cno_connection_t *conn, PyCNO *self, size_t stream, int disconnect)
{
    if (PyErr_Occurred()) {
        return;
    }

    if (self->on_message_end) {
        PyObject *ret = PyObject_CallFunction(self->on_message_end, "ni", stream, disconnect);
        Py_XDECREF(ret);
    }
}


static void pycno_on_write(cno_connection_t *conn, PyCNO *self, const char *data, size_t length)
{
    if (PyErr_Occurred()) {
        return;
    }

    if (self->on_write) {
        PyObject *ret = PyObject_CallFunction(self->on_write, "y#", data, length);
        Py_XDECREF(ret);
    } else if (self->transport) {
        PyErr_Format(PyExc_NotImplementedError, "cannot send to transports yet");
    }
}


static PyCNO * pycno_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    int server  = 1;
    int upgrade = 0;
    char *kwds[] = { "server", "upgrade", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|pp", kwds, &server, &upgrade)) {
        return NULL;
    }

    PyCNO *self = (PyCNO *) type->tp_alloc(type, 0);

    if (self == NULL) {
        return NULL;
    }

    self->conn = cno_connection_new(server, upgrade);

    if (self->conn == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    self->on_write         = NULL;
    self->on_message_start = NULL;
    self->on_message_data  = NULL;
    self->on_message_end   = NULL;
    self->conn->cb_data = self;
    self->conn->on_write         = &pycno_on_write;
    self->conn->on_message_start = &pycno_on_message_start;
    self->conn->on_message_data  = &pycno_on_message_data;
    self->conn->on_message_end   = &pycno_on_message_end;
    return self;
}


static PyObject * pycno_data_received(PyCNO *self, PyObject *args)
{
    const char *data;
    Py_ssize_t length;

    if (!PyArg_ParseTuple(args, "y#", &data, &length)) {
        return NULL;
    }

    if (self->conn == NULL) {
        return PyErr_Format(PyExc_ConnectionError, "connection closed");
    }

    if (cno_connection_data_received(self->conn, data, length)) {
        return pycno_handle_cno_error(self);
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_eof_received(PyCNO *self, PyObject *args)
{
    Py_RETURN_FALSE;
}


static PyObject * pycno_pause_writing(PyCNO *self, PyObject *args)
{
    Py_RETURN_FALSE;
}


static PyObject * pycno_resume_writing(PyCNO *self, PyObject *args)
{
    Py_RETURN_FALSE;
}


static PyObject * pycno_connection_made(PyCNO *self, PyObject *args)
{
    PyObject *transport;

    if (!PyArg_ParseTuple(args, "O", &transport)) {
        return NULL;
    }

    self->transport = transport;
    Py_INCREF(transport);
    Py_RETURN_NONE;
}


static PyObject * pycno_connection_lost(PyCNO *self, PyObject *args)
{
    if (self->transport) {
        Py_DECREF(self->transport);
        self->transport = NULL;
    }

    if (self->conn) {
        if (cno_connection_destroy(self->conn)) {
            return pycno_handle_cno_error(self);
        }

        self->conn = NULL;
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_write_message(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    cno_message_t msg = { 0 };
    PyObject *headers;
    Py_ssize_t stream;

    if (self->conn->server) {
        char *kwds[] = { "stream", "minor", "code", "headers", "chunked", NULL };
        if (!PyArg_ParseTupleAndKeywords(args, kwargs, "niiO|p", kwds, &stream,
                &msg.minor, &msg.code, &headers, &msg.chunked)) {
            return NULL;
        }
    } else {
        char *kwds[] = { "stream", "minor", "method", "path", "headers", "chunked", NULL };
        if (!PyArg_ParseTupleAndKeywords(args, kwargs, "nis#s#O|p", kwds, &stream,
                &msg.minor, &msg.method.data, &msg.method.size,
                &msg.path.data, &msg.path.size, &headers, &msg.chunked)) {
            return NULL;
        }
    }

    msg.headers_len = (size_t) PySequence_Size(headers);

    if (msg.headers_len == (size_t) -1) {
        return PyErr_Format(PyExc_TypeError, "headers must be a sequence of 2-tuples, not %s", Py_TYPE(headers)->tp_name);
    }

    PyObject *iter = PyObject_GetIter(headers);
    PyObject *item;

    if (iter == NULL) {
        return NULL;
    }

    msg.headers = PyMem_RawMalloc(sizeof(cno_header_t) * msg.headers_len);
    cno_header_t *header = msg.headers;

    if (msg.headers == NULL) {
        Py_DECREF(iter);
        return PyErr_NoMemory();
    }

    while ((item = PyIter_Next(iter))) {
        if (!PyArg_ParseTuple(item, "s#s#",
                &header->name.data,  &header->name.size,
                &header->value.data, &header->value.size)) {
            Py_DECREF(item);
            Py_DECREF(iter);
            PyMem_RawFree(msg.headers);
            return NULL;
        }

        Py_DECREF(item);
        ++header;
    }

    Py_DECREF(iter);

    if (PyErr_Occurred()) {
        PyMem_RawFree(msg.headers);
        return NULL;
    }

    if (cno_write_message(self->conn, (size_t) stream, &msg)) {
        return pycno_handle_cno_error(self);
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    PyMem_RawFree(msg.headers);
    Py_RETURN_NONE;
}


static PyObject * pycno_write_data(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    Py_ssize_t stream;
    Py_ssize_t length;
    const char *data;
    int chunked = 0;
    char *kwds[] = { "stream", "data", "chunked", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ny#|p", kwds, &stream, &data, &length, &chunked)) {
        return NULL;
    }

    if (cno_write_data(self->conn, stream, data, length, chunked)) {
        return pycno_handle_cno_error(self);
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pycno_write_end(PyCNO *self, PyObject *args, PyObject *kwargs)
{
    Py_ssize_t stream;
    int chunked = 0;
    char *kwds[] = { "stream", "chunked", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "n|p", kwds, &stream, &chunked)) {
        return NULL;
    }

    if (cno_write_end(self->conn, stream, chunked)) {
        return pycno_handle_cno_error(self);
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}


static void pycno_dealloc(PyCNO *self)
{
    if (self->conn) {
        if (cno_connection_destroy(self->conn)) {
            pycno_handle_cno_error(self);
        }

        self->conn = NULL;
    }

    if (PyErr_Occurred()) {
        PyErr_WriteUnraisable((PyObject *) self);
        PyErr_Clear();
    }

    Py_XDECREF(self->transport);
    Py_XDECREF(self->on_write);
    Py_XDECREF(self->on_message_start);
    Py_XDECREF(self->on_message_data);
    Py_XDECREF(self->on_message_end);
    Py_TYPE(self)->tp_free(self);
}


static PyMethodDef PyCNOMethods[] = {
    { "eof_received",    (PyCFunction) pycno_eof_received,    METH_VARARGS, NULL },
    { "pause_writing",   (PyCFunction) pycno_pause_writing,   METH_VARARGS, NULL },
    { "resume_writing",  (PyCFunction) pycno_resume_writing,  METH_VARARGS, NULL },
    { "data_received",   (PyCFunction) pycno_data_received,   METH_VARARGS, NULL },
    { "connection_made", (PyCFunction) pycno_connection_made, METH_VARARGS, NULL },
    { "connection_lost", (PyCFunction) pycno_connection_lost, METH_VARARGS, NULL },
    { "write_message",   (PyCFunction) pycno_write_message,   METH_VARARGS | METH_KEYWORDS, NULL },
    { "write_data",      (PyCFunction) pycno_write_data,      METH_VARARGS | METH_KEYWORDS, NULL },
    { "write_end",       (PyCFunction) pycno_write_end,       METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


static PyMemberDef PyCNOMembers[] = {
    { "transport",        T_OBJECT_EX, offsetof(PyCNO, transport),        0, NULL },
    { "on_write",         T_OBJECT_EX, offsetof(PyCNO, on_write),         0, NULL },
    { "on_message_start", T_OBJECT_EX, offsetof(PyCNO, on_message_start), 0, NULL },
    { "on_message_data",  T_OBJECT_EX, offsetof(PyCNO, on_message_data),  0, NULL },
    { "on_message_end",   T_OBJECT_EX, offsetof(PyCNO, on_message_end),   0, NULL },
    { NULL }
};


static PyTypeObject PyCNOType = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "pycno.CNO",
    .tp_basicsize = sizeof(PyCNO),
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_new       = (newfunc)    pycno_new,
    .tp_dealloc   = (destructor) pycno_dealloc,
    .tp_methods   = PyCNOMethods,
    .tp_members   = PyCNOMembers,
};


static PyMethodDef functions[] = {
    { NULL }
};


static PyModuleDef module = {
    PyModuleDef_HEAD_INIT, PyModuleDef_NAME, NULL, -1, functions
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
    PyModule_AddObject(m, "CNO", (PyObject*) &PyCNOType);
    return m;
}
