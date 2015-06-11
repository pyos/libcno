import sys
import random
import itertools


LEAF_EOS   = 1
LEAF_CHAR  = 2
LEAF_ERROR = 4
# Upper limit on the contents of the data type used to store tree ids + 1.
TREE_LIMIT = 1 << 16  # unsigned short

TEMPLATE_NODE = '{{{},{},{}}}'
TEMPLATE = '''#include "cno-common.h"

struct cno_st_huffman_item_t {{ unsigned int code; unsigned char bits; }};
struct cno_st_huffman_leaf_t {{ unsigned char type; unsigned char data; unsigned short tree; }};

static const unsigned char CNO_HUFFMAN_LEAF_EOS   = {LEAF_EOS};
static const unsigned char CNO_HUFFMAN_LEAF_CHAR  = {LEAF_CHAR};
static const unsigned char CNO_HUFFMAN_LEAF_ERROR = {LEAF_ERROR};

CNO_STRUCT_EXPORT(huffman_item);
CNO_STRUCT_EXPORT(huffman_leaf);

// How to decode Huffman-encoded strings:
//
//   1. Start with tree id = 0, eos = 1.
//   2. While possible:
//
//      2.1. Read 4 bits of input, set eos = 0.
//      2.2. Look up CNO_HUFFMAN_TREES[tree id | input] to fetch a cno_huffman_leaf_t.
//           If `type` is...
//
//           2.2.1. CNO_HUFFMAN_LEAF_EOS:   set eos = 1
//           2.2.2. CNO_HUFFMAN_LEAF_CHAR:  append character in `data` to output.
//           2.2.3. CNO_HUFFMAN_LEAF_ERROR: return CNO_ERROR_TRANSPORT("invalid Huffman code")
//
//      2.3. set tree id = `tree`.
//
//   3. if eos = 0, return CNO_ERROR_TRANSPORT("truncated Huffman code")
//

static const struct cno_st_huffman_item_t CNO_HUFFMAN_TABLE[] = {{ {TABLE} }};
static const struct cno_st_huffman_leaf_t CNO_HUFFMAN_TREES[] = {{ {TREES} }};
'''


table = [
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
    ( 0x3fffffff, 30),
]

# Left-align and sort by Huffman code so that characters with same bits 0..i
# form a continuous range.
xs = sorted((code << 32 >> sz, sz, i) for i, (code, sz) in enumerate(table))


def make_tree(xs, start, end, i):
    '''
        Construct a Huffman decoder tree.
        Leafs are ints, interior nodes are 2-tuples, invalid nodes are Nones.
    '''
    if end == start or i > 31:
        return None

    if end - start == 1 and xs[start][1] == i:
        return xs[start][2]

    mask = 1 << (31 - i)
    for middle in range(start, end):
        if xs[middle][0] & mask:
            break

    ltree = make_tree(xs, start, middle, i + 1)
    rtree = make_tree(xs, middle, end, i + 1)
    return ltree, rtree


def unwrap(tree):
    '''Recursively enumerate all subtrees.'''
    yield tree
    if isinstance(tree, tuple):
        yield from unwrap(tree[0])
        yield from unwrap(tree[1])


def step(root, tree, seq):
    '''
        Simulate decoding of a sequence starting with `seq` with starting tree `tree`,
        return a (char, tree) tuple where `char` is the character decoded (if any)
        and `tree` is the state in which the decoder would end up.
    '''
    char = None
    seq  = iter(seq)

    while True:
        if tree is None:
            return None, None

        if isinstance(tree, int):
            if char:
                raise ValueError("granularity too low")
            char, tree = tree, root

        try:
            tree = tree[next(seq)]
        except StopIteration:
            break

    if char == 256:
        return None, None

    return char, tree


def gen_header(root, bits_per_step=4):
    '''
        Construct a lookup table that allows to read Huffman-coded data
        `bits_per_step` bits at a time.
    '''
    trees   = list(unwrap(root))
    inputs  = list(itertools.product((0, 1), repeat=bits_per_step))
    require = {root}
    targets = {}

    # Prune unreachable subtrees to improve memory consumption.
    # This can reduce the table size in half.
    for tree in trees:
        for seq in inputs:
            targets[tree, seq] = char, subtree = step(root, tree, seq)
            require.add(subtree)

    trees = list(filter(require.__contains__, trees))

    assert len(trees) <= (TREE_LIMIT >> bits_per_step), 'not enough address space'

    # Find out which states are valid end states. These are precisely those states
    # from which the EOS character (0b1111...1) can be reached.
    eofs = set()
    subtree = root

    while isinstance(subtree, tuple):
        eofs.add(subtree)
        subtree = subtree[1]

    index = dict(zip(trees, itertools.count()))

    for tree in trees:
        for seq in inputs:
            char, subtree = targets[tree, seq]
            eof = LEAF_EOS if subtree in eofs else 0

            if subtree is None:
                yield TEMPLATE_NODE.format(LEAF_ERROR, 0, 0)
            elif char is not None:
                yield TEMPLATE_NODE.format(LEAF_CHAR | eof, char, index[subtree] << bits_per_step)
            else:
                yield TEMPLATE_NODE.format(eof, 0, index[subtree] << bits_per_step)


TREES = ','.join(gen_header(make_tree(xs, 0, len(xs), 0)))
TABLE = ','.join('{{{},{}}}'.format(code, bits) for code, bits in table)

print(TEMPLATE.format_map(globals()))
