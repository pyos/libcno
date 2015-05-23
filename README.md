## CNO

Is it a nuclear fusion cycle? *Or is it a state machine that accepts H(TTP requests)?*

### What?

Ever seen expat? Of course you have. This is pretty much the same thing, but for HTTP:
you feed it some data, and maybe, if you can muster up enough to deduce something
useful from it, some events will be fired.

### Why?

Because we seem to have forgotten what "OSI" is. Because even HTTP 2 "libraries"
are actually servers that are tightly bound to some particular loop. (libuv?! Why, libh2o?
Tell me you're joking.) Because *this* library doesn't care where you get the data.
Bytes in, messages out, no questions asked, and you get to keep your transport-level
secrets to yourself.

```python
class Protocol (asyncio.Protocol):
    def data_received(self, data):
        print('i HAVE the data')
```

### Does it actually work?

Well, it can make and respond to HTTP/1.x requests, upgrade HTTP/1.x connections to HTTP 2,
and respond to the first HEADERS frame with an error because that part is not implemented
yet.

### Then I'm done here.
