CC      = gcc
CFLAGS ?= -O3
PYTHON ?= python3

COMPILE = $(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -fPIC -I. -L./obj -o
DYNLINK = $(CC) -shared -o
ARCHIVE = ar rcs


_require_headers = \
	cno/core.h \
	cno/common.h \
	cno/hpack.h \
	cno/hpack-data.h \
	picohttpparser/picohttpparser.h


_require_objects = \
	obj/core.o \
	obj/common.o \
	obj/hpack.o \
	obj/../picohttpparser/picohttpparser.o \


_require_examples = \
	obj/examples/simple_server \
	obj/examples/simple_client \
	obj/examples/data_loop \
	obj/examples/hpack


.PHONY: all clean
.PRECIOUS: obj/%.o obj/libcno.a obj/libcno.so obj/examples/%


all: $(_require_examples)

obj/libcno.a: $(_require_objects)
	$(DYNLINK) $@ $^

obj/libcno.so: $(_require_objects)
	$(ARCHIVE) $@ $^

obj/%.o: cno/%.c $(_require_headers)
	@mkdir -p obj
	$(COMPILE) $@ $< -c

obj/examples/%: examples/%.c obj/libcno.a
	@mkdir -p obj/examples
	$(COMPILE) $@ $< -lcno -pthread

cno/hpack-data.h: cno/hpack-data.py
	$(PYTHON) cno/hpack-data.py > cno/hpack-data.h

clean:
	rm -rf obj build
