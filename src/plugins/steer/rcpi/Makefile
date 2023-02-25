CC ?= gcc
CFLAGS += -I. -I../../.. -I../../../utils -O2 -Wall -g -Werror

all: rcpi.so

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -I. -I../../.. -I../../../utils -c $< -o $@

rcpi.so: rcpi.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^

clean:
	rm -f *.o *.so*
