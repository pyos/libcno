# Dump the output of this script into `cno-hpack-data.h`.
import itertools

LEAF_EOS   = 1
LEAF_CHAR  = 2
LEAF_ERROR = 4
TREE_LIMIT = 1 << 16  # USHRT_MAX + 1 (because cno_huffman_leaf_t.tree is unsigned short)

STATIC_TABLE = [
    (":authority",                   ""             ), (":method",                      "GET"          ),
    (":method",                      "POST"         ), (":path",                        "/"            ),
    (":path",                        "/index.html"  ), (":scheme",                      "http"         ),
    (":scheme",                      "https"        ), (":status",                      "200"          ),
    (":status",                      "204"          ), (":status",                      "206"          ),
    (":status",                      "304"          ), (":status",                      "400"          ),
    (":status",                      "404"          ), (":status",                      "500"          ),
    ("accept-charset",               ""             ), ("accept-encoding",              "gzip, deflate"),
    ("accept-language",              ""             ), ("accept-ranges",                ""             ),
    ("accept",                       ""             ), ("access-control-allow-origin",  ""             ),
    ("age",                          ""             ), ("allow",                        ""             ),
    ("authorization",                ""             ), ("cache-control",                ""             ),
    ("content-disposition",          ""             ), ("content-encoding",             ""             ),
    ("content-language",             ""             ), ("content-length",               ""             ),
    ("content-location",             ""             ), ("content-range",                ""             ),
    ("content-type",                 ""             ), ("cookie",                       ""             ),
    ("date",                         ""             ), ("etag",                         ""             ),
    ("expect",                       ""             ), ("expires",                      ""             ),
    ("from",                         ""             ), ("host",                         ""             ),
    ("if-match",                     ""             ), ("if-modified-since",            ""             ),
    ("if-none-match",                ""             ), ("if-range",                     ""             ),
    ("if-unmodified-since",          ""             ), ("last-modified",                ""             ),
    ("link",                         ""             ), ("location",                     ""             ),
    ("max-forwards",                 ""             ), ("proxy-authenticate",           ""             ),
    ("proxy-authorization",          ""             ), ("range",                        ""             ),
    ("referer",                      ""             ), ("refresh",                      ""             ),
    ("retry-after",                  ""             ), ("server",                       ""             ),
    ("set-cookie",                   ""             ), ("strict-transport-security",    ""             ),
    ("transfer-encoding",            ""             ), ("user-agent",                   ""             ),
    ("vary",                         ""             ), ("via",                          ""             ),
    ("www-authenticate",             ""             ),
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


def make_tree(xs, start, end, mask):
    '''
        Construct a Huffman decoder tree from a left-aligned table sorted by Huffman code.
        Leafs are ints, interior nodes are 2-tuples, invalid nodes are Nones.
    '''
    if end == start or not mask:
        return None

    for middle, (code, stop, char) in enumerate(xs[start:end], start):
        if stop == mask:  # assuming the code is valid, there is no ambiguity;
            return char   # we've matched a character.
        if code & mask:
            break
    else:
        middle = end  # expect 0 on all valid inputs

    a = make_tree(xs, start, middle, mask >> 1)
    b = make_tree(xs, middle, end, mask >> 1)
    return None if a is b is None else (a, b)


def unwrap(tree):
    '''Recursively enumerate all subtrees.'''
    yield tree
    if isinstance(tree, tuple):
        yield from unwrap(tree[0])
        yield from unwrap(tree[1])


def step(root, tree, seq):
    '''
        Simulate decoding of a sequence starting with `seq` with starting state `tree`,
        return a (char, tree) tuple where `char` is the character decoded (if any)
        and `tree` is the state in which the decoder would end up.
    '''
    char = None
    seq  = iter(seq)

    while tree is not None:
        if isinstance(tree, int):
            if char is not None:
                raise ValueError("can't process that many bits: got 2 chars in 1 step")
            char, tree = tree, root

        try:
            tree = tree[next(seq)]
        except StopIteration:
            break

    return char, tree


def dfa(root, bits_per_step=4):
    '''Construct a DFA that reads Huffman-coded data `bits_per_step` bits at a time.'''
    inputs = list(itertools.product((0, 1), repeat=bits_per_step))
    switch = {tree: {inp: step(root, tree, inp) for inp in inputs} for tree in unwrap(root)}
    accept = {root}

    tree = root
    while isinstance(tree, tuple):
        accept.add(tree)  # coded-string ::= huffman-sequence* '1'*
        tree = tree[1]

    # Sometimes, up to half of the trees are unreachable.
    seen  = {root, None}
    trees = [root]
    for tree in trees:
        for inp in inputs:
            _, st = switch[tree][inp]
            if st not in seen:
                seen.add(st)
                trees.append(st)

    assert len(trees) <= (TREE_LIMIT >> bits_per_step), "you're gonna need a bigger int"

    index = {tree: i << bits_per_step for i, tree in enumerate(trees)}

    for init in trees:
        for inp in inputs:
            char, tree = switch[init][inp]
            eof = LEAF_EOS * (tree in accept)
            yield ((LEAF_ERROR,      0,    0)           if tree is None else
                   (eof,             0,    index[tree]) if char is None else
                   (eof | LEAF_CHAR, char, index[tree]))


ltab = sorted((code << 32 >> sz, 1 << 31 >> sz, i) for i, (code, sz) in enumerate(HUFFMAN))
tree = make_tree(ltab, 0, len(HUFFMAN), 1 << 31)

C_TREES  = ','.join(itertools.starmap('{{{},{},{}}}'.format, dfa(tree)))
C_TABLE  = ','.join(itertools.starmap('{{{},{}}}'.format, HUFFMAN))
C_STATIC = ','.join('{{{{"{}",{}}},{{"{}",{}}}}}'.format(k, len(k), v, len(v)) for k, v in STATIC_TABLE)
C_STSIZE = len(STATIC_TABLE)

print('''// !!! AUTOGENERATED !!! see cno-hpack-huffman.py
static const unsigned char CNO_HUFFMAN_LEAF_EOS   = {LEAF_EOS};
static const unsigned char CNO_HUFFMAN_LEAF_CHAR  = {LEAF_CHAR};
static const unsigned char CNO_HUFFMAN_LEAF_ERROR = {LEAF_ERROR};

typedef struct {{ unsigned int  code; unsigned char bits; }}                      cno_huffman_item_t;
typedef struct {{ unsigned char type; unsigned char data; unsigned short tree; }} cno_huffman_leaf_t;

static const size_t       CNO_HPACK_STATIC_TABLE_SIZE = {C_STSIZE};
static const cno_header_t CNO_HPACK_STATIC_TABLE[]    = {{{C_STATIC}}};
static const cno_huffman_item_t CNO_HUFFMAN_TABLE[] = {{{C_TABLE}}};
static const cno_huffman_leaf_t CNO_HUFFMAN_TREES[] = {{{C_TREES}}};
'''.strip('\n').format_map(globals()))
