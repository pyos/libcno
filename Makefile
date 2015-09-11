CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -I.

HDRS = cno.h cno-common.h cno-hpack.h cno-hpack-data.h picohttpparser/picohttpparser.h
OBJS = cno.o cno-common.o cno-hpack.o                  picohttpparser/picohttpparser.o
EXEC = examples/simple_server examples/simple_client examples/data_loop examples/hpack

.PHONY: all clean
.PRECIOUS: %.o

%.o: %.c $(HDRS)
	$(CC) -c -o "$@" "$<" $(CFLAGS)

examples/%: examples/%.c $(OBJS)
	$(CC) -pthread -o "$@" "$<" $(OBJS) $(CFLAGS)

all: $(EXEC)

clean:
	rm -f $(OBJS) $(EXEC)
