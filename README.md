Socketless HTTP 2.

### Why.

Mostly because libuv, and therefore libh2o, tends to segfault a lot when used
from Python. Also, because why not?

### C API

`make obj/libcno.a`

Just read core.h. All useful functions are at the end of it, and the types are right
above them. Well, except for one: a `cno_buffer_t` (defined in common.h) is just
a `{ char *, size_t }` pair. `CNO_BUFFER_EMPTY` is a zero-initialized one, and
`CNO_BUFFER_STRING(s)` creates one from a null-terminated string. (You'll need this
to construct messages.)

### Python API

`pip3 install git+https://github.com/pyos/libcno`

Requires Python 3.5+, uses asyncio.

```python
import cno

# Extra-high-level client API: simply make a request on a new connection.
# (headers & payload are optional.)
response = await cno.request(event_loop, 'GET', 'https://google.com/',
                             [('user-agent', 'libcno/0.1')], payload=b'')
response  # :: cno.Response
response.code     # :: int
response.headers  # :: [(str, str)]
async for chunk in response.payload:
    chunk  # :: bytes
async for push, pushed_resource_promise in response.pushed:
    push  # :: cno.Request
    await pushed_resource_promise  # :: cno.Response
    # or push.cancel()

response.conn  # :: cno.Client -- implements asyncio.Protocol
response.conn.transport  # :: asyncio.Transport
response.conn.transport.close()  # terminate the connection

# Slightly-lower-level client API: create a new connection (probably for the purposes
# of pooling in HTTP 1 mode/multiplexing in HTTP 2 mode.)
client = await cno.connect(event_loop, 'https://localhost:8000/')
client  # :: cno.Client
client.is_http2  # :: bool
client.scheme    # :: str  -- https
client.authority # :: str  -- localhost:8000

response = await client.request('POST', '/whatever', [('x-whatever', 'whatever')], b'...')
response  # :: cno.Response -- described above

# Even-lower-level client API: just the raw asyncio protocol. `authority` and `scheme`
# are optional, but unless passed to the constructor, they must be sent as
# `:authority` and `:scheme` headers in every request. (This does not actually
# establish a connection to anywhere -- call `event_loop.create_connection`.)
# If the transport is an SSL socket, the protocol is chosen based on ALPN/NPN data.
# Otherwise, pass `force_http2=True` to upgrade through prior knowledge.
protocol = cno.Client(event_loop, authority='localhost:8000', scheme='https')

# Highest-and-lowest-level-possible server API: also a raw protocol.
async def handler(request, loop):
    request.method  # :: str
    request.path    # :: str
    request.headers # :: [(str, str)]
    request.conn    # :: cno.Server
    if not request.conn.is_http2:
        # Go easy on async stuff, as you may accidentally send HTTP 1 responses
        # out of order. And that would be bad.
        pass
    async for chunk in request.payload:
        # Reading the payload is 100% safe, though.
        chunk  # :: bytes
    # Pushed resources must have the same authority and scheme as the request.
    # This method does nothing in HTTP 1 mode.
    request.push('GET', '/index.css', [(':authority', '???'), (':scheme', '???')])
    # content-length is optional in HTTP 2 mode.
    await request.respond(200, [('content-length', '4')], b'!!!\n')
    # Essentially the same as:
    await request.write_headers(200, [('content-length', '4')], final=False)
    await request.write_data(b'!!!', final=False)
    await request.write_data(b'\n', final=True)
    # Note that sending a response will most likely close the stream, cancelling
    # this coroutine.

protocol = cno.Server(event_loop, handler)
# server = await event_loop.create_server(lambda: protocol, '', 8000, ssl=...)
```
