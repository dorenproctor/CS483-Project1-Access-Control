CFLAGS=-g -std=c99 -pedantic -Wall

all: get put

get: get.o
	gcc get.o -o get
	chmod u+s get

get.o: get.c
	gcc -c $(CFLAGS) get.c

put: put.o
	gcc put.o -o put
	chmod u+s put

put.o: put.c
	gcc -c $(CFLAGS) put.c

clean:
	rm -f get get.o put put.o
