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
        # Can you do that, libuv? CAN YOU?
        print('i HAVE the data', data)
```

### Does it actually work?

Not yet.

### Then I'm done here.
