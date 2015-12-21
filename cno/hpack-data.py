import os
import textwrap
import itertools


LEAF_OK    = 1
LEAF_CHAR  = 2
TREE_LIMIT = 1 << 16  # because cno_huffman_leaf_t.tree is uint16_t

STATIC_TABLE = [
    (":authority",          ""           ), (":method",                     "GET"          ),
    (":method",             "POST"       ), (":path",                       "/"            ),
    (":path",               "/index.html"), (":scheme",                     "http"         ),
    (":scheme",             "https"      ), (":status",                     "200"          ),
    (":status",             "204"        ), (":status",                     "206"          ),
    (":status",             "304"        ), (":status",                     "400"          ),
    (":status",             "404"        ), (":status",                     "500"          ),
    ("accept-charset",      ""           ), ("accept-encoding",             "gzip, deflate"),
    ("accept-language",     ""           ), ("accept-ranges",               ""             ),
    ("accept",              ""           ), ("access-control-allow-origin", ""             ),
    ("age",                 ""           ), ("allow",                       ""             ),
    ("authorization",       ""           ), ("cache-control",               ""             ),
    ("content-disposition", ""           ), ("content-encoding",            ""             ),
    ("content-language",    ""           ), ("content-length",              ""             ),
    ("content-location",    ""           ), ("content-range",               ""             ),
    ("content-type",        ""           ), ("cookie",                      ""             ),
    ("date",                ""           ), ("etag",                        ""             ),
    ("expect",              ""           ), ("expires",                     ""             ),
    ("from",                ""           ), ("host",                        ""             ),
    ("if-match",            ""           ), ("if-modified-since",           ""             ),
    ("if-none-match",       ""           ), ("if-range",                    ""             ),
    ("if-unmodified-since", ""           ), ("last-modified",               ""             ),
    ("link",                ""           ), ("location",                    ""             ),
    ("max-forwards",        ""           ), ("proxy-authenticate",          ""             ),
    ("proxy-authorization", ""           ), ("range",                       ""             ),
    ("referer",             ""           ), ("refresh",                     ""             ),
    ("retry-after",         ""           ), ("server",                      ""             ),
    ("set-cookie",          ""           ), ("strict-transport-security",   ""             ),
    ("transfer-encoding",   ""           ), ("user-agent",                  ""             ),
    ("vary",                ""           ), ("via",                         ""             ),
    ("www-authenticate",    ""           ),
]

HUFFMAN = [  # char code -> (right-aligned huffman code, bit length)
    (     0x1ff8, 13), (   0x7fffd8, 23 ), (  0xfffffe2, 28 ), (  0xfffffe3, 28 ),
    (  0xfffffe4, 28), (  0xfffffe5, 28 ), (  0xfffffe6, 28 ), (  0xfffffe7, 28 ),
    (  0xfffffe8, 28), (   0xffffea, 24 ), ( 0x3ffffffc, 30 ), (  0xfffffe9, 28 ),
    (  0xfffffea, 28), ( 0x3ffffffd, 30 ), (  0xfffffeb, 28 ), (  0xfffffec, 28 ),
    (  0xfffffed, 28), (  0xfffffee, 28 ), (  0xfffffef, 28 ), (  0xffffff0, 28 ),
    (  0xffffff1, 28), (  0xffffff2, 28 ), ( 0x3ffffffe, 30 ), (  0xffffff3, 28 ),
    (  0xffffff4, 28), (  0xffffff5, 28 ), (  0xffffff6, 28 ), (  0xffffff7, 28 ),
    (  0xffffff8, 28), (  0xffffff9, 28 ), (  0xffffffa, 28 ), (  0xffffffb, 28 ),
    (       0x14,  6), (      0x3f8, 10 ), (      0x3f9, 10 ), (      0xffa, 12 ),
    (     0x1ff9, 13), (       0x15,  6 ), (       0xf8,  8 ), (      0x7fa, 11 ),
    (      0x3fa, 10), (      0x3fb, 10 ), (       0xf9,  8 ), (      0x7fb, 11 ),
    (       0xfa,  8), (       0x16,  6 ), (       0x17,  6 ), (       0x18,  6 ),
    (        0x0,  5), (        0x1,  5 ), (        0x2,  5 ), (       0x19,  6 ),
    (       0x1a,  6), (       0x1b,  6 ), (       0x1c,  6 ), (       0x1d,  6 ),
    (       0x1e,  6), (       0x1f,  6 ), (       0x5c,  7 ), (       0xfb,  8 ),
    (     0x7ffc, 15), (       0x20,  6 ), (      0xffb, 12 ), (      0x3fc, 10 ),
    (     0x1ffa, 13), (       0x21,  6 ), (       0x5d,  7 ), (       0x5e,  7 ),
    (       0x5f,  7), (       0x60,  7 ), (       0x61,  7 ), (       0x62,  7 ),
    (       0x63,  7), (       0x64,  7 ), (       0x65,  7 ), (       0x66,  7 ),
    (       0x67,  7), (       0x68,  7 ), (       0x69,  7 ), (       0x6a,  7 ),
    (       0x6b,  7), (       0x6c,  7 ), (       0x6d,  7 ), (       0x6e,  7 ),
    (       0x6f,  7), (       0x70,  7 ), (       0x71,  7 ), (       0x72,  7 ),
    (       0xfc,  8), (       0x73,  7 ), (       0xfd,  8 ), (     0x1ffb, 13 ),
    (    0x7fff0, 19), (     0x1ffc, 13 ), (     0x3ffc, 14 ), (       0x22,  6 ),
    (     0x7ffd, 15), (        0x3,  5 ), (       0x23,  6 ), (        0x4,  5 ),
    (       0x24,  6), (        0x5,  5 ), (       0x25,  6 ), (       0x26,  6 ),
    (       0x27,  6), (        0x6,  5 ), (       0x74,  7 ), (       0x75,  7 ),
    (       0x28,  6), (       0x29,  6 ), (       0x2a,  6 ), (        0x7,  5 ),
    (       0x2b,  6), (       0x76,  7 ), (       0x2c,  6 ), (        0x8,  5 ),
    (        0x9,  5), (       0x2d,  6 ), (       0x77,  7 ), (       0x78,  7 ),
    (       0x79,  7), (       0x7a,  7 ), (       0x7b,  7 ), (     0x7ffe, 15 ),
    (      0x7fc, 11), (     0x3ffd, 14 ), (     0x1ffd, 13 ), (  0xffffffc, 28 ),
    (    0xfffe6, 20), (   0x3fffd2, 22 ), (    0xfffe7, 20 ), (    0xfffe8, 20 ),
    (   0x3fffd3, 22), (   0x3fffd4, 22 ), (   0x3fffd5, 22 ), (   0x7fffd9, 23 ),
    (   0x3fffd6, 22), (   0x7fffda, 23 ), (   0x7fffdb, 23 ), (   0x7fffdc, 23 ),
    (   0x7fffdd, 23), (   0x7fffde, 23 ), (   0xffffeb, 24 ), (   0x7fffdf, 23 ),
    (   0xffffec, 24), (   0xffffed, 24 ), (   0x3fffd7, 22 ), (   0x7fffe0, 23 ),
    (   0xffffee, 24), (   0x7fffe1, 23 ), (   0x7fffe2, 23 ), (   0x7fffe3, 23 ),
    (   0x7fffe4, 23), (   0x1fffdc, 21 ), (   0x3fffd8, 22 ), (   0x7fffe5, 23 ),
    (   0x3fffd9, 22), (   0x7fffe6, 23 ), (   0x7fffe7, 23 ), (   0xffffef, 24 ),
    (   0x3fffda, 22), (   0x1fffdd, 21 ), (    0xfffe9, 20 ), (   0x3fffdb, 22 ),
    (   0x3fffdc, 22), (   0x7fffe8, 23 ), (   0x7fffe9, 23 ), (   0x1fffde, 21 ),
    (   0x7fffea, 23), (   0x3fffdd, 22 ), (   0x3fffde, 22 ), (   0xfffff0, 24 ),
    (   0x1fffdf, 21), (   0x3fffdf, 22 ), (   0x7fffeb, 23 ), (   0x7fffec, 23 ),
    (   0x1fffe0, 21), (   0x1fffe1, 21 ), (   0x3fffe0, 22 ), (   0x1fffe2, 21 ),
    (   0x7fffed, 23), (   0x3fffe1, 22 ), (   0x7fffee, 23 ), (   0x7fffef, 23 ),
    (    0xfffea, 20), (   0x3fffe2, 22 ), (   0x3fffe3, 22 ), (   0x3fffe4, 22 ),
    (   0x7ffff0, 23), (   0x3fffe5, 22 ), (   0x3fffe6, 22 ), (   0x7ffff1, 23 ),
    (  0x3ffffe0, 26), (  0x3ffffe1, 26 ), (    0xfffeb, 20 ), (    0x7fff1, 19 ),
    (   0x3fffe7, 22), (   0x7ffff2, 23 ), (   0x3fffe8, 22 ), (  0x1ffffec, 25 ),
    (  0x3ffffe2, 26), (  0x3ffffe3, 26 ), (  0x3ffffe4, 26 ), (  0x7ffffde, 27 ),
    (  0x7ffffdf, 27), (  0x3ffffe5, 26 ), (   0xfffff1, 24 ), (  0x1ffffed, 25 ),
    (    0x7fff2, 19), (   0x1fffe3, 21 ), (  0x3ffffe6, 26 ), (  0x7ffffe0, 27 ),
    (  0x7ffffe1, 27), (  0x3ffffe7, 26 ), (  0x7ffffe2, 27 ), (   0xfffff2, 24 ),
    (   0x1fffe4, 21), (   0x1fffe5, 21 ), (  0x3ffffe8, 26 ), (  0x3ffffe9, 26 ),
    (  0xffffffd, 28), (  0x7ffffe3, 27 ), (  0x7ffffe4, 27 ), (  0x7ffffe5, 27 ),
    (    0xfffec, 20), (   0xfffff3, 24 ), (    0xfffed, 20 ), (   0x1fffe6, 21 ),
    (   0x3fffe9, 22), (   0x1fffe7, 21 ), (   0x1fffe8, 21 ), (   0x7ffff3, 23 ),
    (   0x3fffea, 22), (   0x3fffeb, 22 ), (  0x1ffffee, 25 ), (  0x1ffffef, 25 ),
    (   0xfffff4, 24), (   0xfffff5, 24 ), (  0x3ffffea, 26 ), (   0x7ffff4, 23 ),
    (  0x3ffffeb, 26), (  0x7ffffe6, 27 ), (  0x3ffffec, 26 ), (  0x3ffffed, 26 ),
    (  0x7ffffe7, 27), (  0x7ffffe8, 27 ), (  0x7ffffe9, 27 ), (  0x7ffffea, 27 ),
    (  0x7ffffeb, 27), (  0xffffffe, 28 ), (  0x7ffffec, 27 ), (  0x7ffffed, 27 ),
    (  0x7ffffee, 27), (  0x7ffffef, 27 ), (  0x7fffff0, 27 ), (  0x3ffffee, 26 ),
]


def huffman_to_tree(xs, max_code_length=32):
    def branch(xs, i):
        if not xs or i > max_code_length:
            return None

        for middle, (code, length, char) in enumerate(xs):
            if length < i:
                # got enough bits to decode a character.
                return char
            if (code << i) & (1 << length):
                # `middle` is the first entry with 1 at i-th most significant bit.
                break
        else:
            # all valid codes have 0 as i-th bit.
            middle = len(xs)

        a = branch(xs[:middle], i + 1)
        b = branch(xs[middle:], i + 1)
        return None if a is b is None else (a, b)

    return branch(sorted((c, s, i) for i, (c, s) in enumerate(xs)), 1)


def flatten(tree):
    yield tree
    if isinstance(tree, tuple):
        yield from flatten(tree[0])
        yield from flatten(tree[1])


def step(root, state, seq):
    # feed some bits to the huffman decoder dfa. returns (decoded char, new state).
    char = False
    while state is not None:
        if isinstance(state, int):
            assert char is False, 'a single step would yield multiple characters'
            char, state = state, root
        else:
            try:
                state = state[next(seq)]
            except StopIteration:
                break
    return char, state


def huffman_dfa(root, bits_per_step=4):
    inputs = list(itertools.product((0, 1), repeat=bits_per_step))
    # given a huffman tree (essentially a dfa that consumes bits), construct a dfa
    # that takes multiple bits at a time as input. to run the dfa, start from state 0.
    # take the current state, bitwise-or with the input, then use the result as an index
    # into the array. this will yield a (flags, char, next state) tuple.
    # states marked with LEAF_OK are the accepting states. ones with LEAF_CHAR
    # have decoded a character which must be appended to the output.
    switch = {(state, inp): step(root, state, iter(inp)) for state in flatten(root) for inp in inputs}
    # a complete encoded sequence must decode to some characters and optionally
    # be padded with 1-s until the nearest octet boundary. thus the states reachable
    # from the 0-th state by following 1-branches are exactly the accepting ones.
    tree = root
    accept = set()
    for _ in range(8):  # "padded to nearest octet boundary" => 0-7 ones.
        accept.add(tree)
        if isinstance(tree, tuple):
            tree = tree[1]
    assert None not in accept, 'an invalid state is also accepting'

    reachable = [root]
    for state in reachable:
        for inp in inputs:
            _, next_state = switch[state, inp]
            if next_state not in reachable:
                reachable.append(next_state)
    assert len(reachable) <= (TREE_LIMIT >> bits_per_step), "you're gonna need a bigger int"
    print(len(reachable), 'states')

    for state in reachable:
        for inp in inputs:
            char, next_state = switch[state, inp]
            flags  = LEAF_OK   if next_state in accept else 0
            flags |= LEAF_CHAR if char is not False    else 0
            yield (flags, int(char), reachable.index(next_state) << bits_per_step)


with open(os.path.join(os.path.dirname(__file__), 'hpack-data.h'), 'w') as fd:
    s = textwrap.dedent(
    '''
    // make cno/hpack-data.h
    struct cno_huffman_item_t {{ uint32_t code; uint8_t bits; }};
    struct cno_huffman_leaf_t {{ uint8_t  type; uint8_t data; uint16_t tree; }};

    static const uint8_t CNO_HUFFMAN_LEAF_OK    = {};
    static const uint8_t CNO_HUFFMAN_LEAF_CHAR  = {};

    static const struct cno_header_t CNO_HPACK_STATIC_TABLE[]  = {{ {} }};
    static const struct cno_huffman_item_t CNO_HUFFMAN_TABLE[] = {{ {} }};
    static const struct cno_huffman_leaf_t CNO_HUFFMAN_TREES[] = {{ {} }};
    static const size_t CNO_HPACK_STATIC_TABLE_SIZE = sizeof(CNO_HPACK_STATIC_TABLE) / sizeof(struct cno_header_t);
    '''
    )
    print(s.format(
        LEAF_OK, LEAF_CHAR,
        ','.join('{{"%s",%s},{"%s",%s}}' % (k, len(k), v, len(v)) for k, v in STATIC_TABLE),
        ','.join('{%s,%s}'    % h for h in HUFFMAN),
        ','.join('{%s,%s,%s}' % h for h in huffman_dfa(huffman_to_tree(HUFFMAN))),
    ), file=fd)
