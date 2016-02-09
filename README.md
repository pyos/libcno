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
response.payload  # :: asyncio.StreamReader
async for push in response.pushed:
    push.method   # :: str
    push.path     # :: str
    push.headers  # :: [(str, str)]
    await push.response  # :: cno.Response
    # or push.cancel()

response.conn  # :: cno.Client -- implements asyncio.Protocol
response.conn.loop       # :: asyncio.BaseEventLoop
response.conn.transport  # :: asyncio.Transport
response.conn.transport.close()

# Slightly-lower-level client API: create a new connection (probably for the purposes
# of pooling in HTTP 1 mode/multiplexing in HTTP 2 mode.)
client = await cno.connect(event_loop, 'https://localhost:8000/')
client  # :: cno.Client
client.is_http2  # :: bool
client.scheme    # :: str  -- https
client.authority # :: str  -- localhost:8000

response = await client.request('POST', '/whatever', [('x-whatever', 'whatever')], b'...')
response  # :: cno.Response

# Even-lower-level client API: just the raw asyncio protocol. `authority` and `scheme`
# are optional, but unless passed to the constructor, they must be sent as
# `:authority` and `:scheme` headers in every request. (This does not actually
# establish a connection to anywhere -- call `event_loop.create_connection`.)
# If the transport is an SSL socket, the protocol is chosen based on ALPN/NPN data.
# Otherwise, pass `force_http2=True` to upgrade through prior knowledge.
protocol = cno.Client(event_loop, authority='localhost:8000', scheme='https')

# Highest-and-lowest-level-possible server API: also a raw protocol.
async def handle(request):
    request  # :: cno.Request
    request.method   # :: str
    request.path     # :: str
    request.headers  # :: [(str, str)]
    request.conn     # :: cno.Server
    request.payload  # :: asyncio.StreamReader

    # Pushed resources must have the same :authority and :scheme as the request.
    request.push('GET', '/index.css', [(':authority', '???'), (':scheme', '???')])

    if all_data_is_available:
        await request.respond(200, [('content-length', '4')], b'!!!\n')
    else:
        # `Channel` is a subclass of `asyncio.Queue`.
        channel = cno.Channel(max_buffered_chunks, loop=request.conn.loop)
        await channel.put(b'!!!')  # this should preferably be done in a separate
        await channel.put(b'\n')   # coroutine, naturally.
        channel.close()
        await request.respond(200, [], channel)

protocol = cno.Server(event_loop, handle)
# server = await event_loop.create_server(lambda: protocol, '', 8000, ssl=...)
```
