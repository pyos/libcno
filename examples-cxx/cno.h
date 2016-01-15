#ifndef CNO_CXX_H
#define CNO_CXX_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cno/core.h>
#include "aio.h"


namespace cno
{
    struct header
    {
        // same layout as cno_header_t
        const aio::stringview name;
        const aio::stringview value;
        header(const aio::stringview k, const aio::stringview v) : name(k), value(v) {}
    };

    struct message
    {
        // same layout as cno_message_t
        const int code;
        const aio::stringview method;
        const aio::stringview path;
        const header *headers;
        const size_t  headers_len;

        typedef const header * iterator;
        iterator begin () const { return headers; }
        iterator end   () const { return headers + headers_len; }
    };

    struct stream
    {
        uint32_t id;
        struct cno_connection_t * const connection;
        bool sent_all = false;

        std::string buffer;
        aio::event<int> on_drain;

        stream(struct cno_connection_t *conn, uint32_t id) : id(id), connection(conn) {}
        stream(stream const &)  = delete;
        stream(stream const &&) = delete;
        stream& operator = (stream const &)  = delete;
        stream& operator = (stream const &&) = delete;

        int on_message (const message &);
        int on_data    (const aio::stringview);
        int on_end     ();

        int reset()
        {
            return cno_write_reset(connection, id);
        }

        int write_message(int code, const std::vector<header> &hs)
        {
            struct cno_header_t  *h = (struct cno_header_t *) &hs[0];
            struct cno_message_t cm = { code, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, h, hs.size() };
            return cno_write_message(connection, id, &cm, 0);
        }

        int write_message(const aio::stringview method,
                          const aio::stringview path, const std::vector<header> &hs)
        {
            struct cno_header_t  *h = (struct cno_header_t *) &hs[0];
            struct cno_message_t cm = { 0, { (char *) method.base, method.size },
                                           { (char *) path.base,   path.size   }, h, hs.size() };
            return cno_write_message(connection, id, &cm, sent_all = false);
        }

        int write_data(const aio::stringview buf)
        {
            if (buffer.append(buf.base, buf.size).size() == buf.size)
                return on_flow();

            return CNO_OK;
        }

        int write_eof()
        {
            sent_all = true;

            if (buffer.empty())
                // on_flow will do nothing, but we should send an empty DATA frame
                // with the EOS flag set.
                return cno_write_data(connection, id, "", 0, 1);

            return CNO_OK;
        }

        int on_flow()
        {
            if (!buffer.size())
                return CNO_OK;

            int32_t written = cno_write_data(connection, id, buffer.data(), buffer.size(), sent_all);

            if (written < 0)
                return CNO_ERROR_UP();

            if (buffer.erase(0, written).empty())
                // if a stream implementation generates data incrementally,
                // it may subscribe to on_drain before calling write_data
                // and pause processing until the whole contents of the buffer
                // are sent before writing the next chunk.
                on_drain.emit();

            return CNO_OK;
        }
    };

    template <typename stream_t, enum CNO_CONNECTION_KIND kind> struct protocol : aio::protocol
    {
        struct cno_connection_t conn;
        std::unordered_map<uint32_t, stream_t *> streams;

        protocol(aio::transport *t) : aio::protocol(t)
        {
            cno_connection_init(&conn, kind);
            conn.cb_data = this;
            conn.on_write         = (decltype(conn.on_write))         &on_write;
            conn.on_stream_start  = (decltype(conn.on_stream_start))  &on_stream;
            conn.on_stream_end    = (decltype(conn.on_stream_end))    &on_stream_end;
            conn.on_message_start = (decltype(conn.on_message_start)) &on_message;
            conn.on_message_data  = (decltype(conn.on_message_data))  &on_message_data;
            conn.on_message_end   = (decltype(conn.on_message_end))   &on_message_end;
            conn.on_flow_increase = (decltype(conn.on_flow_increase)) &on_flow;

            if (cno_connection_made(&conn, CNO_HTTP1))
                // TODO log errors
                transport->close();
        }

        virtual ~protocol()
        {
            if (cno_connection_lost(&conn))
                // TODO log errors
                {}
            cno_connection_reset(&conn);
            for (auto &it : streams) delete it.second;
        }

        int data_received(const struct aio::stringview data) override
        {
            if (cno_connection_data_received(&conn, data.base, data.size))
                // TODO log errors
                transport->close_on_drain();

            return 0;
        }

        static int on_write(protocol *p, const char *data, size_t size)
        {
            p->transport->write({ data, size });
            return CNO_OK;
        }

        static int on_stream(protocol *p, uint32_t id)
        {
            p->streams[id] = new stream_t{&p->conn, id};
            return CNO_OK;
        }

        static int on_stream_end(protocol *p, uint32_t id)
        {
            auto it = p->streams.find(id);
            delete it->second;
            p->streams.erase(it);
            return CNO_OK;
        }

        static int on_message(protocol *p, uint32_t id, const struct cno_message_t *msg)
        {
            return p->streams[id]->on_message(*(const message *) msg);
        }

        static int on_message_data(protocol *p, uint32_t id, const char *data, size_t size)
        {
            return p->streams[id]->on_data({ data, size });
        }

        static int on_message_end(protocol *p, uint32_t id)
        {
            return p->streams[id]->on_end();
        }

        static int on_flow(protocol *p, uint32_t id)
        {
            if (id)
                return p->streams[id]->on_flow();

            for (auto &it : p->streams)
                if (it.second->on_flow())
                    return CNO_ERROR_UP();

            return CNO_OK;
        }
    };
};

#endif