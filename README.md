## CNO

Is it a nuclear fusion cycle? *Or is it a state machine that accepts H(TTP requests)?*

### What?

Ever seen expat? Of course you have. This is pretty much the same thing, but for HTTP:
you feed it some data, and maybe, if you can muster up enough to deduce something
useful from it, some events will be fired.

### Why?

Because we seem to have forgotten what "OSI" is. Because even HTTP 2 "libraries"
are actually servers that are tightly bound to some particular loop. Because *this*
library doesn't care where you get the data. Bytes in, messages out, or the other way
around, no questions asked, and you get to keep your transport-level secrets to yourself.

```python
class Protocol (asyncio.Protocol):
    def data_received(self, data):
        print('i HAVE the data')
```

### Does it actually work?

No idea.

  * On the one hand, you can create a client and a server and they can successfully send
    HTTP 2 messages to each other.
  * On the other hand, that means absolutely nothing.
  * *But* the server also replies correctly to nghttp, and the client can make requests to
    nghttpd. So I guess it works?

HTTP/1.1 mode definitely works, though.

### Then I'm done here.
