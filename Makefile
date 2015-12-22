CC       ?= gcc
CXX      ?= g++
CFLAGS   ?= -O3
CXXFLAGS ?= -O3
PYTHON   ?= python3

ifeq ($(STRICT),1)
_options += -DCNO_HTTP2_ENFORCE_MESSAGING_RULES
endif

COMPILE = $(CC)  $(CFLAGS)   -std=c11   -Wall -Wextra -Werror -Wno-unused-parameter -fPIC -I. -o
COMPCPP = $(CXX) $(CXXFLAGS) -std=c++11 -Wall -Wextra -Werror -I. -o
DYNLINK = $(CC) -shared -o
ARCHIVE = ar rcs


_require_headers = \
	cno/core.h       \
	cno/hpack.h      \
	cno/hpack-data.h \
	cno/common.h     \
	picohttpparser/picohttpparser.h


_require_objects = \
	obj/common.o   \
	obj/hpack.o    \
	obj/core.o     \
	obj/../picohttpparser/picohttpparser.o


_require_examples = \
	obj/examples-cpp/server    \
	obj/examples/simple_server \
	obj/examples/simple_client \
	obj/examples/data_loop     \
	obj/examples/hpack


.PHONY: all clean
.PRECIOUS: obj/%.o obj/libcno.a obj/libcno.so obj/examples/%


all: obj/libcno.a

obj/libcno.so: $(_require_objects)
	$(DYNLINK) $@ $^

obj/libcno.a: $(_require_objects)
	$(ARCHIVE) $@ $^

obj/%.o: cno/%.c $(_require_headers)
	@mkdir -p obj
	$(COMPILE) $@ $< -c $(_options)

obj/examples/%: examples/%.c obj/libcno.a
	@mkdir -p obj/examples
	$(COMPILE) $@ $< -L./obj -lcno -pthread

obj/examples-cxx/%: examples-cxx/%.cc obj/libcno.a
	@mkdir -p obj/examples-cxx
	$(COMPCPP) $@ $< -L./obj -lcno -pthread

cno/hpack-data.h: cno/hpack-data.py
	$(PYTHON) cno/hpack-data.py

clean:
	rm -rf obj build
