CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -fPIC -I. -L.

HDRS = cno.h cno-common.h cno-hpack.h picohttpparser/picohttpparser.h cno-hpack-data.h
OBJS = cno.o cno-common.o cno-hpack.o picohttpparser/picohttpparser.o
EXEC = examples/simple_server examples/simple_client examples/data_loop examples/hpack

.PHONY: all clean
.PRECIOUS: %.o

all: $(EXEC)

clean:
	rm -f $(OBJS) $(EXEC) libcno.a libcno.so

libcno.a: $(OBJS)
	ar rcs $@ $^

libcno.so: $(OBJS)
	$(CC) -shared -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

examples/%: examples/%.c libcno.a
	$(CC) $(CFLAGS) -pthread -o $@ $< -lcno
