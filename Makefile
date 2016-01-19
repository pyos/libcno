CC       ?= gcc
CFLAGS   ?= -O3
PYTHON   ?= python3

COMPILE = $(CC)  $(CFLAGS)   -std=c11   -Wall -Wextra -Werror -fPIC -I. -o
DYNLINK = $(CC) -shared -o
ARCHIVE = ar rcs


_require_headers = \
	cno/config.h     \
	cno/core.h       \
	cno/hpack.h      \
	cno/hpack-data.h \
	cno/common.h     \
	picohttpparser/picohttpparser.h


_require_objects = \
	obj/picohttpparser.o \
	obj/common.o         \
	obj/hpack.o          \
	obj/core.o


.PHONY: all clean
.PRECIOUS: obj/%.o obj/libcno.a obj/libcno.so


all: obj/libcno.a

picohttpparser/.git: .gitmodules
	git submodule update --init picohttpparser

obj/libcno.so: $(_require_objects)
	$(DYNLINK) $@ $^

obj/libcno.a: $(_require_objects)
	$(ARCHIVE) $@ $^

obj/picohttpparser.o: picohttpparser/.git
	@mkdir -p obj
	$(COMPILE) $@ picohttpparser/picohttpparser.c -c

obj/%.o: cno/%.c $(_require_headers)
	@mkdir -p obj
	$(COMPILE) $@ $< -c

cno/hpack-data.h: cno/hpack-data.py
	$(PYTHON) cno/hpack-data.py

clean:
	rm -rf obj build
