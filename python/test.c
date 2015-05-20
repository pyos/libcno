//! file: ../src/core.c
//! file: ../src/iovec.c
//! file: ../src/error.c
//! file: ../picohttpparser/picohttpparser.c
//! include_dir: ..
//! include_dir: ../include
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include "core.h"
#include "error.h"


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


static void pycno_on_message_start(cno_connection_t *conn, PyCNO *self, size_t stream, cno_message_t *msg)
{
    if (PyErr_Occurred()) {
        return;
    }

    if (self->on_message_start) {
        PyObject *headers = PyDict_New();
        size_t i;

        if (headers == NULL) {
            return;
        }

        for (i = 0; i < msg->headers_len; ++i) {
            PyObject *name  = PyUnicode_FromStringAndSize(msg->headers[i].name.data, msg->headers[i].name.size);

            if (name == NULL) {
                Py_DECREF(headers);
                return;
            }

            PyObject *value = PyUnicode_FromStringAndSize(msg->headers[i].value.data, msg->headers[i].value.size);

            if (value == NULL) {
                Py_DECREF(headers);
                Py_DECREF(name);
                return;
            }

            if (PyDict_SetItem(headers, name, value)) {
                Py_DECREF(headers);
                Py_DECREF(value);
                Py_DECREF(name);
                return;
            }

            Py_DECREF(value);
            Py_DECREF(name);
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
        cno_connection_destroy(self->conn);
        self->conn = NULL;
        return PyErr_Format(PyExc_RuntimeError, "%d: %s (%s:%d)", cno_error(), cno_error_text(), cno_error_file(), cno_error_line());
    }

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
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
        cno_connection_destroy(self->conn);
        self->conn = NULL;
    }

    Py_RETURN_NONE;
}


static void pycno_dealloc(PyCNO *self)
{
    cno_connection_destroy(self->conn);
    self->conn = NULL;
    Py_XDECREF(self->transport);
    Py_XDECREF(self->on_write);
    Py_XDECREF(self->on_message_start);
    Py_XDECREF(self->on_message_data);
    Py_XDECREF(self->on_message_end);
    Py_TYPE(self)->tp_free(self);
}


static PyMethodDef PyCNOMethods[] = {
    { "data_received",   (PyCFunction) pycno_data_received,   METH_VARARGS, NULL },
    { "connection_made", (PyCFunction) pycno_connection_made, METH_VARARGS, NULL },
    { "connection_lost", (PyCFunction) pycno_connection_lost, METH_VARARGS, NULL },
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
